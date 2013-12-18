/*
 * Copyright (C) 2009-2013 Typesafe Inc. <http://www.typesafe.com>
 */
package play.api.libs.json

import Json._
import play.api.data.mapping._

class JsSuccess[T](override val value: T, val path: JsPath = JsPath()) extends Success[(JsPath, Seq[ValidationError]), T](value) {
  override def toString = s"JsSuccess($value, $path)"
  override def equals(o: Any) = {
    if (canEqual(o)) {
      val j = o.asInstanceOf[JsSuccess[T]]
      this.value == j.value && this.path == j.path
    } else false
  }
  override def hashCode = 41 * (41 + value.hashCode) + path.hashCode
  override def canEqual(o: Any) = o.isInstanceOf[JsSuccess[T]]
}

object JsSuccess {
  def apply[T](value: T, path: JsPath = JsPath()) = new JsSuccess(value, path)
  // unapply just ignore path. I (jto) don't think it's an issue since applicativeJsResult removes it anyway.
  def unapply[T](s: Success[(JsPath, Seq[ValidationError]), T]) = Some(s.value -> JsPath())
}

class JsError(override val errors: Seq[(JsPath, Seq[ValidationError])]) extends Failure[(JsPath, Seq[ValidationError]), Nothing](errors) {
  override def get: Nothing = throw new NoSuchElementException("JsError.get")

  def ++(error: JsError): JsError = JsError.merge(this, error)

  def :+(error: (JsPath, ValidationError)): JsError = JsError.merge(this, JsError(error))
  def append(error: (JsPath, ValidationError)): JsError = this.:+(error)

  def +:(error: (JsPath, ValidationError)): JsError = JsError.merge(JsError(error), this)
  def prepend(error: (JsPath, ValidationError)): JsError = this.+:(error)

  override def toString = s"JsError($errors)"
  override def hashCode = errors.hashCode
  override def equals(o: Any) = {
    if (canEqual(o)) {
      val j = o.asInstanceOf[JsError]
      this.errors == j.errors
    } else false
  }

  override def canEqual(o: Any) = o.isInstanceOf[JsError]
}

object JsError {

  def apply(errors: Seq[(Path, Seq[ValidationError])]): JsError = new JsError(errors.map {
    case (JsPath(p), errs) => JsPath(p) -> errs
    case (p, errs) => JsPath(p) -> errs
  })

  def apply(): JsError = JsError(Seq(JsPath() -> Seq()))
  def apply(error: ValidationError): JsError = JsError(Seq(JsPath() -> Seq(error)))
  def apply(error: String): JsError = JsError(ValidationError(error))
  def apply(error: (JsPath, ValidationError)): JsError = JsError(Seq(error._1 -> Seq(error._2)))
  def apply(path: JsPath, error: ValidationError): JsError = JsError(path -> error)
  def apply(path: JsPath, error: String): JsError = JsError(path -> ValidationError(error))

  def unapply[T](f: Failure[(JsPath, Seq[ValidationError]), T]) = Some(f.errors)

  def merge(e1: Seq[(JsPath, Seq[ValidationError])], e2: Seq[(JsPath, Seq[ValidationError])]): Seq[(JsPath, Seq[ValidationError])] = {
    (e1 ++ e2).groupBy(_._1).mapValues(_.map(_._2).flatten).toList
  }

  def merge(e1: JsError, e2: JsError): JsError = {
    JsError(merge(e1.errors, e2.errors))
  }

  //def toJson: JsValue = original // TODO
  //def toJsonErrorsOnly: JsValue = original // TODO

  def toFlatForm[O](e: Failure[(Path, Seq[ValidationError]), O]) = e.errors.map { case (path, seq) => JsPath(path).toJsonString -> seq }
  def toFlatJson(e: JsError): JsObject = toFlatJson(e.errors)
  def toFlatJson[O](e: Failure[(Path, Seq[ValidationError]), O]): JsObject = toFlatJson(e.errors)
  def toFlatJson(errors: Seq[(Path, Seq[ValidationError])]): JsObject =
    errors.foldLeft(Json.obj()) { (obj, error) =>
      obj ++ Json.obj(JsPath(error._1).toJsonString -> error._2.foldLeft(Json.arr()) { (arr, err) =>
        arr :+ play.api.data.mapping.json.Writes.validationError.writes(err)
      })
    }
}
