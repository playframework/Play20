package play.api.data.mapping.json

import play.api.libs.json._

// Backward compat
trait WithRepath[A] {
  import play.api.data.mapping._
  val self: Validation[(JsPath, Seq[ValidationError]), A]

  def repath(path: JsPath): JsResult[A] = self match {
    case JsSuccess(a, p) => JsSuccess(a, path ++ p)
    case JsError(es) => JsError(es.map { case (p, s) => path ++ p -> s })
  }
}

object Rules extends play.api.data.mapping.DefaultRules[JsValue] {
  import scala.language.implicitConversions
  import play.api.libs.functional._
  import play.api.libs.functional.syntax._

  import play.api.data.mapping._ // We need that import to shadow Json PathNodes types
  import play.api.libs.json.{ KeyPathNode => JSKeyPathNode, IdxPathNode => JIdxPathNode }
  private def pathToJsPath(p: Path) =
    play.api.libs.json.JsPath(p.path.map {
      case KeyPathNode(key) => JSKeyPathNode(key)
      case IdxPathNode(i) => JIdxPathNode(i)
    })

  private def jsonAs[T](f: PartialFunction[JsValue, Validation[ValidationError, T]])(args: Any*) =
    Rule.fromMapping[JsValue, T](
      f.orElse {
        case j => Failure(Seq(ValidationError("error.invalid", args: _*)))
      })

  implicit def string = jsonAs[String] {
    case JsString(v) => Success(v)
  }("String")

  implicit def boolean = jsonAs[Boolean] {
    case JsBoolean(v) => Success(v)
  }("Boolean")

  // Note: Mappings of JsNumber to Number are validating that the JsNumber is indeed valid
  // in the target type. i.e: JsNumber(4.5) is not considered parseable as an Int.
  // That's a bit stricter than the "old" Read, which just cast to the target type, possibly loosing data.
  implicit def int = jsonAs[Int] {
    case JsNumber(v) if v.isValidInt => Success(v.toInt)
  }("Int")

  implicit def short = jsonAs[Short] {
    case JsNumber(v) if v.isValidShort => Success(v.toShort)
  }("Short")

  implicit def long = jsonAs[Long] {
    case JsNumber(v) if v.isValidLong => Success(v.toLong)
  }("Long")

  implicit def jsNumber = jsonAs[JsNumber] {
    case v @ JsNumber(_) => Success(v)
  }("Number")

  implicit def jsBoolean = jsonAs[JsBoolean] {
    case v @ JsBoolean(_) => Success(v)
  }("Boolean")

  implicit def jsString = jsonAs[JsString] {
    case v @ JsString(_) => Success(v)
  }("String")

  implicit def jsObject = jsonAs[JsObject] {
    case v @ JsObject(_) => Success(v)
  }("Object")

  implicit def jsArray = jsonAs[JsArray] {
    case v @ JsArray(_) => Success(v)
  }("Array")

  // BigDecimal.isValidFloat is buggy, see [SI-6699]
  import java.{ lang => jl }
  private def isValidFloat(bd: BigDecimal) = {
    val d = bd.toFloat
    !d.isInfinity && bd.bigDecimal.compareTo(new java.math.BigDecimal(jl.Float.toString(d), bd.mc)) == 0
  }
  implicit def float = jsonAs[Float] {
    case JsNumber(v) if isValidFloat(v) => Success(v.toFloat)
  }("Float")

  // BigDecimal.isValidDouble is buggy, see [SI-6699]
  private def isValidDouble(bd: BigDecimal) = {
    val d = bd.toDouble
    !d.isInfinity && bd.bigDecimal.compareTo(new java.math.BigDecimal(jl.Double.toString(d), bd.mc)) == 0
  }
  implicit def double = jsonAs[Double] {
    case JsNumber(v) if isValidDouble(v) => Success(v.toDouble)
  }("Double")

  implicit def bigDecimal = jsonAs[BigDecimal] {
    case JsNumber(v) => Success(v)
  }("BigDecimal")

  import java.{ math => jm }
  implicit def javaBigDecimal = jsonAs[jm.BigDecimal] {
    case JsNumber(v) => Success(v.bigDecimal)
  }("BigDecimal")

  implicit val jsNull = jsonAs[JsNull.type] {
    case JsNull => Success(JsNull)
  }("null")

  implicit def ooo[O](p: Path)(implicit pick: Path => Rule[JsValue, JsValue], coerce: Rule[JsValue, O]): Rule[JsValue, Option[O]] =
    option(Rule.zero[O])(pick, coerce)(p)

  def option[J, O](r: => Rule[J, O], noneValues: Rule[JsValue, JsValue]*)(implicit pick: Path => Rule[JsValue, JsValue], coerce: Rule[JsValue, J]): Path => Rule[JsValue, Option[O]] = super.opt[J, O](r, (jsNull.fmap(n => n: JsValue) +: noneValues): _*)

  implicit def map[O](implicit r: Rule[JsValue, O]): Rule[JsValue, Map[String, O]] =
    super.map[JsValue, O](r, jsObject.fmap { case JsObject(fs) => fs })

  implicit def pickInJson[O](p: Path)(implicit r: Rule[JsValue, O]): Rule[JsValue, O] =
    Rule[JsValue, JsValue] { json =>
      pathToJsPath(p)(json) match {
        case Nil => Failure(Seq(Path -> Seq(ValidationError("error.required"))))
        case js :: _ => Success(js)
      }
    }.compose(r)

  // // XXX: a bit of boilerplate
  private def pickInS[T](implicit r: Rule[Seq[JsValue], T]): Rule[JsValue, T] =
    jsArray.fmap { case JsArray(fs) => fs }.compose(r)
  implicit def pickSeq[O](implicit r: Rule[JsValue, O]) = pickInS(seq[JsValue, O])
  implicit def pickSet[O](implicit r: Rule[JsValue, O]) = pickInS(set[JsValue, O])
  implicit def pickList[O](implicit r: Rule[JsValue, O]) = pickInS(list[JsValue, O])
  implicit def pickArray[O: scala.reflect.ClassTag](implicit r: Rule[JsValue, O]) = pickInS(array[JsValue, O])
  implicit def pickTraversable[O](implicit r: Rule[JsValue, O]) = pickInS(traversable[JsValue, O])

}