package play.api.libs.json

import play.api.data.validation.ValidationError

sealed trait PathNode {
  def apply(json: JsValue): List[JsValue]
  def toJsonString: String

  private[json] def splitChildren(json: JsValue): List[Either[(PathNode, JsValue), (PathNode, JsValue)]]
  def set(json: JsValue, transform: JsValue => JsValue): JsValue

  private[json] def toJsonField(value: JsValue): JsValue = value

}

case class RecursiveSearch(key: String) extends PathNode {
  def apply(json: JsValue): List[JsValue] = json match {
    case obj: JsObject => (json \\ key).toList.filterNot{ 
      case JsUndefined(_) => true 
      case _ => false
    }
    case _ => List()
  }
  override def toString = "//" + key
  def toJsonString = "*" + key

  /**
   * First found, first set and never goes down after setting
   */
  def set(json: JsValue, transform: JsValue => JsValue): JsValue = json match {
    case obj: JsObject => 
      var found = false 
      val o = JsObject(obj.fields.map{ case (k,v) => 
        if(k == this.key) { 
          found = true
          k -> transform(v) 
        }
        else k -> set(v, transform) 
      })

      o
    case _ => json
  }  

  private[json] def splitChildren(json: JsValue) = json match {
    case obj: JsObject => obj.fields.toList.map{ case (k,v) => 
      if(k == this.key) Right(this -> v)
      else Left(KeyPathNode(k) -> v)
    }
    case arr: JsArray => 
      arr.value.toList.zipWithIndex.map{ case (js, j) => Left(IdxPathNode(j) -> js) }
    
    case _ => List()
  } 
}
 
case class KeyPathNode(key: String) extends PathNode{

  def apply(json: JsValue): List[JsValue] = json match {
    case obj: JsObject => List(json \ key).filterNot{ 
      case JsUndefined(_) => true 
      case _ => false
    }
    case _ => List()
  }

  override def toString = "/" + key
  def toJsonString = "." + key

  def set(json: JsValue, transform: JsValue => JsValue): JsValue = json match {
    case obj: JsObject => 
      var found = false 
      val o = JsObject(obj.fields.map{ case (k,v) => 
        if(k == this.key) { 
          found = true
          k -> transform(v) 
        }
        else k -> v 
      })
      if(!found) o ++ Json.obj(this.key -> transform(Json.obj()))
      else o
    case _ => transform(json)
  }

  private[json] def splitChildren(json: JsValue) = json match {
    case obj: JsObject => obj.fields.toList.map{ case (k,v) => 
      if(k == this.key) Right(this -> v)
      else Left(KeyPathNode(k) -> v)
    }
    case _ => List()
  } 

  private[json] override def toJsonField(value: JsValue) = Json.obj(key -> value)

}

case class IdxPathNode(idx: Int) extends PathNode {
  def apply(json: JsValue): List[JsValue] = json match {
    case arr: JsArray => List(arr(idx))
    case _ => List()
  }

  override def toString = "(%d)".format(idx)
  def toJsonString = "[%d]".format(idx)

  def set(json: JsValue, transform: JsValue => JsValue): JsValue = json match {
    case arr: JsArray => JsArray(arr.value.zipWithIndex.map{ case (js, j) => if(j == idx) transform(js) else js})
    case _ => transform(json)
  }

  private[json] def splitChildren(json: JsValue) = json match {
    case arr: JsArray => arr.value.toList.zipWithIndex.map{ case (js, j) => 
      if(j == idx) Right(this -> js) 
      else Left(IdxPathNode(j) -> js)
    }
    case _ => List()
  } 

  private[json] override def toJsonField(value: JsValue) = value

}

object __ extends JsPath

object JsPath {
  def \(child: String) = JsPath() \ child
  def \(child: Symbol) = JsPath() \ child

  def \\(child: String) = JsPath() \\ child
  def \\(child: Symbol) = JsPath() \\ child

  def apply(idx: Int): JsPath = JsPath()(idx)

  // TODO implement it correctly (doesn't merge )
  def createObj(pathValues: (JsPath, JsValue)*) = {

    def buildSubPath(path: JsPath, value: JsValue) = {
      def step(path: List[PathNode], value: JsValue): JsObject = {
        path match {
          case List() => value match {
            case obj @ JsObject(_) => obj
            case _ => throw new RuntimeException("when empty JsPath, expecting JsObject")
          }
          case List(p) => p match {
            case KeyPathNode(key) => Json.obj(key -> value)
            case _ => throw new RuntimeException("expected KeyPathNode")
          }
          case head :: tail => head match {
            case KeyPathNode(key) => Json.obj(key -> step(tail, value))
            case _ => throw new RuntimeException("expected KeyPathNode")
          }
        }
      }

      step(path.path, value)
    }

    pathValues.foldLeft(Json.obj()){ (obj, pv) => 
      val (path, value) = (pv._1, pv._2)
      val subobj = buildSubPath(path, value)
      obj.deepMerge(subobj)
    }
  }
}

case class JsPath(path: List[PathNode] = List()) {
  def \(child: String) = JsPath(path :+ KeyPathNode(child))
  def \(child: Symbol) = JsPath(path :+ KeyPathNode(child.name))

  def \\(child: String) = JsPath(path :+ RecursiveSearch(child))
  def \\(child: Symbol) = JsPath(path :+ RecursiveSearch(child.name))

  def apply(idx: Int): JsPath = JsPath(path :+ IdxPathNode(idx))

  def apply(json: JsValue): List[JsValue] =  path.foldLeft(List(json))((s,p) => s.flatMap(p.apply))

  def asSingleJsResult(json: JsValue): JsResult[JsValue] = this(json) match {
    case Nil => JsError(Seq(this -> Seq(ValidationError("validate.error.missing-path"))))
    case List(js) => JsSuccess(js)
    case head :: tail => JsError(Seq(this -> Seq(ValidationError("validate.error.multiple-result-path"))))
  }

  def asSingleJson(json: JsValue): JsValue = this(json) match {
    case Nil => JsUndefined("not.found")
    case List(js) => js
    case head::tail => JsUndefined("multiple.result")
  }

  override def toString = path.mkString
  def toJsonString = path.foldLeft("obj")((acc, p) => acc + p.toJsonString)

  def compose(other: JsPath) = JsPath(path ++ other.path)
  def ++(other: JsPath) = this compose other

  /**
   * Reads/Writes/Format builders
   */
  def read[T](implicit r: Reads[T]) = Reads.at[T](this)(r)
  def readOpt[T](implicit r: Reads[T]) = Reads.optional[T](this)(r)

  def write[T](implicit w: Writes[T]) = Writes.at[T](this)(w)
  def write[T](t: T)(implicit w: Writes[T]) = Writes.fixedValue(this, t)

  def rw[T](implicit r:Reads[T], w:Writes[T]) = Format.at[T](this)(Format(r, w))

  def format[T](implicit f: Format[T]) = Format.at[T](this)(f)
  def format[T](r: Reads[T])(implicit w: Writes[T]) = Format.at[T](this)(Format(r, w))
  def format[T](w: Writes[T])(implicit r: Reads[T]) = Format.at[T](this)(Format(r, w))

  private val self = this

  object json {
    def pick: OWrites[JsValue] = Writes.pick(self)
    def put(w: Writes[JsValue]): OWrites[JsValue] = Writes.at(self)(w)
    def put(js: JsValue)(implicit w: Writes[JsValue]): OWrites[JsValue] = self.write(js)
    def modify(w: Writes[JsValue]): OWrites[JsValue] = Writes.modifyJson(self)(w)
    def transform(f: JsValue => JsValue): OWrites[JsValue] = Writes.transformJson(self, f)  
  }
  


}
