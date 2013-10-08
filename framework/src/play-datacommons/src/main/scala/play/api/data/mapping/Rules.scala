package play.api.data.mapping

/**
* Play provides you a `Map[String, Seq[String]]` (aliased as `UrlFormEncoded`) in request body for urlFormEncoded requests.
* It's generally a lot more convenient to work on `Map[Path, Seq[String]]` to define Rules.
* This object contains methods used to convert `Map[String, Seq[String]]` <-> `Map[Path, Seq[String]]`
* @note We use the alias `UrlFormEncoded`, which is just a `Map[String, Seq[String]]`
*/
object PM {

  import scala.util.parsing.combinator.{ Parsers, RegexParsers }
  /**
  * A parser converting a key of a Map[String, [Seq[String]]] to a Path instance
  * `foo.bar[0].baz` becomes `Path \ "foo" \ "bar" \ 0 \ "baz"`
  */
  object PathParser extends RegexParsers {
    override type Elem = Char
    def int   = """\d""".r ^^ { _.toInt }
    def idx   = "[" ~> int <~ "]" ^^ { IdxPathNode(_) }
    def key   = rep1(not("." | idx) ~> ".".r) ^^ { ks => KeyPathNode(ks.mkString) }
    def node  = key ~ opt(idx) ^^ { case k ~ i => k :: i.toList }
    def path  = (opt(idx) ~ repsep(node, ".")) ^^ { case i ~ ns => Path(i.toList ::: ns.flatten) }

    def parse(s: String) = parseAll(path, new scala.util.parsing.input.CharArrayReader(s.toArray))
  }

  type PM = Map[Path, Seq[String]]

  /**
  * Find a sub-Map of all the elements at a Path starting with `path`
  * @param path The prefix to look for
  * @param data The map in which you want to lookup
  * @return a sub Map. If no key of `data` starts with `path`, this map will be empty
  */
  def find(path: Path)(data: PM): PM = data.flatMap {
    case (p, errs) if p.path.startsWith(path.path) =>
      Map(Path(p.path.drop(path.path.length)) -> errs)
    case _ =>
      Map.empty[Path, Seq[String]]
  }

  /**
  * Apply `f` to all the keys of `m`
  */
  def repathPM(m: PM, f: Path => Path): PM
    = m.map{ case (p, v) => f(p) -> v }

  /**
  * Apply `f` to all the keys of `m`
  */
  def repath(m: UrlFormEncoded, f: Path => Path): UrlFormEncoded
    = toM(repathPM(toPM(m), f))

  /**
  * Convert a Map[String, Seq[String]] to a Map[Path, Seq[String]]
  */
  def toPM(m: UrlFormEncoded): PM =
    m.map { case (p, v) => asPath(p) -> v }

  /**
  * Convert a Map[Path, Seq[String]] to a Map[String, Seq[String]]
  */
  def toM(m: PM): UrlFormEncoded =
    m.map { case (p, v) => asKey(p) -> v }

  private def asNodeKey(n: PathNode): String = n match {
    case IdxPathNode(i) => s"[$i]"
    case KeyPathNode(k) => k
  }

  /**
  * Convert a Path to a String key
  * @param p The path to convert
  * @return A String representation of `p`
  */
  def asKey(p: Path): String = p.path.headOption.toList.map(asNodeKey).mkString ++ p.path.tail.foldLeft("") {
    case (path, n@IdxPathNode(i)) => path + asNodeKey(n)
    case (path, n@KeyPathNode(k)) => path + "." + asNodeKey(n)
  }

  /**
  * Convert a String key to a Path using `PathParser`
  * @param k The String representation of path to convert
  * @return a `Path`
  */
  def asPath(k: String): Path = PathParser.parse(k) match {
    case PathParser.Failure(m, _) => throw new RuntimeException(s"Invalid field name $k: $m")
    case PathParser.Error(m, _) => throw new RuntimeException(s"Invalid field name $k: $m")
    case PathParser.Success(r, _) => r
  }
}

/**
 * This object provides Rules for Map[String, Seq[String]]
 */
object Rules extends DefaultRules[PM.PM] with ParsingRules {
  import scala.language.implicitConversions
  import play.api.libs.functional._
  import play.api.libs.functional.syntax._

  import PM._

  // implicit def pickInRequest[I, O](p: Path[Request[I]])(implicit pick: Path[I] => Mapping[String, I, O]): Mapping[String, Request[I], O] =
  //   request => pick(Path[I](p.path))(request.body)

  implicit def map[O](implicit r: Rule[Seq[String], O]): Rule[PM, Map[String, O]] = {
    val toSeq = Rule.zero[PM].fmap(_.toSeq.map { case (k, v) =>  asKey(k) -> v })
    super.map[Seq[String], O](r,  toSeq)
  }

  def pmPick[O](implicit p: Path => Rule[UrlFormEncoded, O]): Path => Rule[PM, O] =
    path => Rule { pm => p(path).validate(toM(pm)) }

  implicit def conv = Rule[PM, UrlFormEncoded] { pm => Success(toM(pm))}
  implicit def conv2[O](implicit r: Rule[UrlFormEncoded, O]) =
    Rule.zero[PM].fmap(toM _).compose(r)

  implicit def option[O](implicit coerce: Rule[PM, O]): Path => Rule[UrlFormEncoded, Option[O]] =
    path => {
      Rule.zero[UrlFormEncoded].fmap(toPM)
        .compose{
          val pick = pmPick(mapPick(Rule.zero[PM]))
          super.option(coerce)(pick)(path)
        }
    }

  def option[J, O](r: Rule[J, O])(implicit coerce: Rule[PM, J]): Path => Rule[UrlFormEncoded, Option[O]] =
    this.option(coerce compose r)

  implicit def pick[O](implicit r: Rule[Seq[String], O]): Rule[PM, O] = Rule[PM, Seq[String]] { pm =>
    val vs = pm.toSeq.flatMap {
      case (Path, vs) => Seq(0 -> vs)
      case (Path(Seq(IdxPathNode(i))), vs) => Seq(i -> vs)
      case _ => Seq()
    }.sortBy(_._1).flatMap(_._2)
    Success(vs)
  }.compose(r)

  implicit def mapPick[O](implicit r: Rule[PM, O]): Path => Rule[UrlFormEncoded, O] =
    (path: Path) =>
      Rule.fromMapping[UrlFormEncoded, PM] { data =>
        PM.find(path)(toPM(data)) match {
          case s if s.isEmpty => Failure(Seq(ValidationError("validation.required")))
          case s => Success(s)
        }
      }.compose(r)

  implicit def mapPickSeqMap(p: Path) = Rule.fromMapping[UrlFormEncoded, Seq[UrlFormEncoded]]({ data =>
    val grouped = PM.find(p)(PM.toPM(data)).toSeq.flatMap {
      case (Path, vs) => Seq(0 -> Map(Path -> vs))
      case (Path(IdxPathNode(i) :: Nil) \: t, vs) => Seq(i -> Map(t -> vs))
      case _ => Nil
    }.groupBy(_._1).mapValues(_.map(_._2)) // returns all the submap, grouped by index

    val submaps = grouped.toSeq.map {
      case (i, ms) => i -> ms.foldLeft(Map.empty[Path, Seq[String]]) { _ ++ _ } // merge the submaps by index
    }.sortBy(_._1).map(e => PM.toM(e._2))

    submaps match {
      case s if s.isEmpty => Failure(Seq(ValidationError("validation.required")))
      case s => Success(s)
    }
  })

}