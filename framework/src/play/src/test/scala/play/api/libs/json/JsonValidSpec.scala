package play.api.libs.json

import org.specs2.mutable._
import play.api.libs.json._
import play.api.libs.json.Json._
import scala.util.control.Exception._
import java.text.ParseException
import play.api.data.validation.ValidationError
import Reads.constraints._
import play.api.libs.json.util._


object JsonValidSpec extends Specification {
  "JSON reads" should {
    "validate simple types" in {
      JsString("string").validate[String] must equalTo(JsSuccess("string"))
      JsNumber(5).validate[Int] must equalTo(JsSuccess(5))
      JsNumber(5L).validate[Long] must equalTo(JsSuccess(5L))
      JsNumber(5).validate[Short] must equalTo(JsSuccess(5))
      JsNumber(123.5).validate[Float] must equalTo(JsSuccess(123.5))
      JsNumber(123456789123456.567891234).validate[Double] must equalTo(JsSuccess(123456789123456.567891234))
      JsBoolean(true).validate[Boolean] must equalTo(JsSuccess(true))
    }

    "invalidate wrong simple type conversion" in {
      JsString("string").validate[Long] must equalTo(JsError(Seq(JsPath() -> Seq(ValidationError("validate.error.expected.jsnumber")))))
      JsNumber(5).validate[String] must equalTo(JsError(Seq(JsPath() -> Seq(ValidationError("validate.error.expected.jsstring")))))
      JsBoolean(false).validate[Double] must equalTo(JsError(Seq(JsPath() -> Seq(ValidationError("validate.error.expected.jsnumber")))))
    }

    "validate simple numbered type conversion" in {
      JsNumber(5).validate[Double] must equalTo(JsSuccess(5.0))
      JsNumber(5.123).validate[Int] must equalTo(JsSuccess(5))
      JsNumber(BigDecimal(5)).validate[Double] must equalTo(JsSuccess(5.0))
      JsNumber(5.123).validate[BigDecimal] must equalTo(JsSuccess(BigDecimal(5.123)))
    }

    "validate JsObject to Map" in {
      Json.obj("key1" -> "value1", "key2" -> "value2").validate[Map[String, String]] must equalTo(JsSuccess(Map("key1" -> "value1", "key2" -> "value2")))
      Json.obj("key1" -> 5, "key2" -> 3).validate[Map[String, Int]] must equalTo(JsSuccess(Map("key1" -> 5, "key2" -> 3)))
      Json.obj("key1" -> 5.123, "key2" -> 3.543).validate[Map[String, Float]] must equalTo(JsSuccess(Map("key1" -> 5.123F, "key2" -> 3.543F)))
      Json.obj("key1" -> 5.123, "key2" -> 3.543).validate[Map[String, Double]] must equalTo(JsSuccess(Map("key1" -> 5.123, "key2" -> 3.543)))
    }

    "invalidate JsObject to Map with wrong type conversion" in {
      Json.obj("key1" -> "value1", "key2" -> "value2", "key3" -> "value3").validate[Map[String, Int]] must equalTo(
        JsError(Seq(
          JsPath \ "key1" -> Seq(ValidationError("validate.error.expected.jsnumber")),
          JsPath \ "key2" -> Seq(ValidationError("validate.error.expected.jsnumber")),
          JsPath \ "key3" -> Seq(ValidationError("validate.error.expected.jsnumber"))
        ))
      )

      Json.obj("key1" -> "value1", "key2" -> 5, "key3" -> true).validate[Map[String, Int]] must equalTo(
        JsError(Seq(
          JsPath \ "key1" -> Seq(ValidationError("validate.error.expected.jsnumber")),
          JsPath \  "key3" -> Seq(ValidationError("validate.error.expected.jsnumber"))
        ))
      )
    }

    "validate JsArray to List" in {
      Json.arr("alpha", "beta", "delta").validate[List[String]] must equalTo(JsSuccess(List("alpha", "beta", "delta")))
      Json.arr(123, 567, 890).validate[List[Int]] must equalTo(JsSuccess(List(123, 567, 890)))
      Json.arr(123.456, 567.123, 890.654).validate[List[Int]] must equalTo(JsSuccess(List(123, 567, 890)))
      Json.arr(123.456, 567.123, 890.654).validate[List[Double]] must equalTo(JsSuccess(List(123.456, 567.123, 890.654)))
    }

    "invalidate JsArray to List with wrong type conversion" in {
      Json.arr("alpha", "beta", "delta").validate[List[Int]] must equalTo(
        JsError(Seq(
          JsPath(0) -> Seq(ValidationError("validate.error.expected.jsnumber")),
          JsPath(1) -> Seq(ValidationError("validate.error.expected.jsnumber")),
          JsPath(2) -> Seq(ValidationError("validate.error.expected.jsnumber"))
        ))
      )

      Json.arr("alpha", 5, true).validate[List[Int]] must equalTo(
        JsError(Seq(
          JsPath(0) -> Seq(ValidationError("validate.error.expected.jsnumber")),
          JsPath(2) -> Seq(ValidationError("validate.error.expected.jsnumber"))
        ))
      )
    }

    "validate Dates" in {
      val d = new java.util.Date()
      val df = new java.text.SimpleDateFormat("yyyy-MM-dd")
      val dd = df.parse(df.format(d))

      Json.toJson[java.util.Date](dd).validate[java.util.Date] must beEqualTo(JsSuccess(dd))
      JsNumber(dd.getTime).validate[java.util.Date] must beEqualTo(JsSuccess(dd))

      val dj = new org.joda.time.DateTime()
      val dfj = org.joda.time.format.DateTimeFormat.forPattern("yyyy-MM-dd")
      val ddj = org.joda.time.DateTime.parse(dfj.print(dj), dfj)

      Json.toJson[org.joda.time.DateTime](ddj).validate[org.joda.time.DateTime] must beEqualTo(JsSuccess(ddj))
      JsNumber(ddj.getMillis).validate[org.joda.time.DateTime] must beEqualTo(JsSuccess(ddj))

      val ds = new java.sql.Date(dd.getTime())

      Json.toJson[java.sql.Date](ds).validate[java.sql.Date] must beEqualTo(JsSuccess(dd))
      JsNumber(dd.getTime).validate[java.sql.Date] must beEqualTo(JsSuccess(dd))

      // very poor test to do really crappy java date APIs
      val c = java.util.Calendar.getInstance()
      c.setTime(new java.util.Date(d.getTime - d.getTime % 1000))
      val tz = c.getTimeZone().getOffset(c.getTime.getTime).toInt / 3600000
      val js = JsString(
        "%04d-%02d-%02dT%02d:%02d:%02d%s%02d:00".format(
          c.get(java.util.Calendar.YEAR), 
          c.get(java.util.Calendar.MONTH) + 1, 
          c.get(java.util.Calendar.DAY_OF_MONTH), 
          c.get(java.util.Calendar.HOUR_OF_DAY), 
          c.get(java.util.Calendar.MINUTE), 
          c.get(java.util.Calendar.SECOND),
          if(tz>0) "+" else "-",
          tz
        )
      )
      js.validate[java.util.Date](Reads.IsoDateReads) must beEqualTo(JsSuccess(c.getTime))
    }

  }

  "JSON caseclass/tuple validation" should {
    case class User(name: String, age: Int)

    /*implicit val UserFormat = new Format[User]{
      def reads(json: JsValue): JsResult[User] = (at[String](JsPath \ "name") ~> minLength[String](5)).reads(json).map( User(_) )
      def writes(user: User): JsValue = Json.obj("name" -> user.name)
    }*/


    /*implicit val UserFormat = JsMapper(
      at[String](JsPath \ "name")(minLength(5)))
      ~ at[Int](JsPath \ "age")
    )(User.apply)(User.unapply)*/

    "validate simple reads" in {
      JsString("alphabeta").validate[String] must equalTo(JsSuccess("alphabeta"))
    }

    "validate simple constraints" in {
      JsString("alphabeta").validate[String](Reads.minLength(5)) must equalTo(JsSuccess("alphabeta"))
    }

    "test JsPath.create" in {
      val obj = JsPath.createObj( 
        JsPath \ "toto" \ "toto1" -> JsString("alpha"),
        JsPath \ "titi" \ "titi1" -> JsString("beta"),
        JsPath \ "titi" \ "titi2" -> JsString("beta2")
      )
      print("OBJ:%s".format(obj))
      success
    }
    
    "validate simple case class reads/writes" in {
      val bobby = User("bobby", 54)

      implicit val userReads = { import Reads.path._
      (
        at(JsPath \ "name")(minLength[String](5)) 
        and 
        at(JsPath \ "age")(min(40))
      )(User) }

      implicit val userWrites = { import Writes.path._
      (
        at[String](JsPath \ "name")
        and 
        at[Int](JsPath \ "age")
      )(unlift(User.unapply)) }

      val js = Json.toJson(bobby)

      println("JSON:%s".format(js))
      
      js.validate[User] must equalTo(JsSuccess(bobby))
    }

    "validate simple case class format" in {
      val bobby = User("bobby", 54)

      implicit val userFormats = { import Format.path._; import Format.constraints._
      (
        at(JsPath \ "name")(Format(minLength[String](5), of[String]))
        and 
        at(JsPath \ "age")(Format(min(40), of[Int]))
      )(User, unlift(User.unapply)) }

      val js = Json.toJson(bobby)

      println("JSON:%s".format(js))
      
      js.validate[User] must equalTo(JsSuccess(bobby))
    }

    "validate simple case class format" in {
      val bobby = User("bobby", 54)

      implicit val userFormats = { import Format.path._; import Format.constraints._
      (
        (__ \ "name").rw(minLength[String](5), of[String])
        and 
        (__ \ "age").rw(min(40), of[Int])
      ) apply (User, unlift(User.unapply))
     }

      val js = Json.toJson(bobby)

      println("JSON:%s".format(js))
      
      js.validate[User] must equalTo(JsSuccess(bobby))
    }
    
    "JsObject tupled reads" in {
      implicit val dataReads: Reads[(String, Int)] = { import Reads.path._
        (
          at[String]( __ \ "uuid" ) and 
          at[Int]( __ \ "nb" )
        ) tupled
      }

      val js = Json.obj(
        "uuid" -> "550e8400-e29b-41d4-a716-446655440000",
        "nb" -> 654
      )

      js.validate[(String, Int)] must equalTo(JsSuccess("550e8400-e29b-41d4-a716-446655440000" -> 654))
    }

    "JsObject tupled reads new syntax" in {
      implicit val dataReads: Reads[(String, Int)] = (
        ( __ \ "uuid" ).read[String] and 
        ( __ \ "nb" ).read[Int]
      ) tupled

      val js = Json.obj(
        "uuid" -> "550e8400-e29b-41d4-a716-446655440000",
        "nb" -> 654
      )

      js.validate[(String, Int)] must equalTo(JsSuccess("550e8400-e29b-41d4-a716-446655440000" -> 654))
    }

    "JsObject tupled writes" in {
      implicit val dataWrites: Writes[(String, Int)] = (
        ( __ \ "uuid" ).write[String] and
        ( __ \ "nb" ).write[Int]
      ) tupled

      val js = Json.obj(
        "uuid" -> "550e8400-e29b-41d4-a716-446655440000",
        "nb" -> 654
      )

      Json.toJson("550e8400-e29b-41d4-a716-446655440000" -> 654) must equalTo(js)
    }

    "JsObject tupled format" in {
      implicit val dataFormat: Format[(String, Int)] = (
        ( __ \ "uuid" ).format[String] and
        ( __ \ "nb" ).format[Int]
      ) tupled

      val js = Json.obj(
        "uuid" -> "550e8400-e29b-41d4-a716-446655440000",
        "nb" -> 654
      )

      Json.toJson("550e8400-e29b-41d4-a716-446655440000" -> 654) must equalTo(js)
      js.validate[(String, Int)] must equalTo(JsSuccess("550e8400-e29b-41d4-a716-446655440000" -> 654))
    }

    "Format simpler syntax without constraints" in {
      val bobby = User("bobby", 54)

      implicit val userFormats = { 
      (
        (__ \ 'name).format[String] 
        and 
        (__ \ 'age).format[Int]
      )(User, unlift(User.unapply)) }

      val js = Json.toJson(bobby)

      js.validate[User] must equalTo(JsSuccess(bobby))
    }

    "Format simpler syntax with constraints" in {
      val bobby = User("bobby", 54)

      implicit val userFormats = (
        (__ \ 'name).format(minLength[String](5)) 
        and 
        (__ \ 'age).format(min(40))
      )(User, unlift(User.unapply))

      val js = Json.toJson(bobby)

      js.validate[User] must equalTo(JsSuccess(bobby))
    }
  }

  "JSON Writes tools for Json" should {
    "Build JSON from JSON using Writes flattened" in {
      val js = Json.obj(
        "key1" -> "value1",
        "key2" -> Json.obj(
          "key21" -> 123,
          "key22" -> Json.obj("key222" -> "blabla"),
          "key23" -> true
        ),
        "key3" -> Json.arr("alpha", "beta", "gamma")
      )

      val jsonTransformer = (
        (__ \ "key1").json.pick and
        (__ \ "key2").json.modify(
          (
            (__ \ "key21").json.pick and
            (__ \ "key22").json.transform( js => js \ "key222" )
          ) join
        ) and
        (__ \ "key3").json.transform( js => js.as[JsArray] ++ Json.arr("delta")) and
        (__ \ "key4").json.put(
          (
            (__ \ "key41").json.put(JsNumber(345)) and
            (__ \ "key42").json.put(JsString("alpha"))
          ) join
        )
      ) join

      val res = Json.obj(
        "key1" -> "value1",
        "key2" -> Json.obj(
          "key21" -> 123,
          "key22" -> "blabla",
          "key23" -> true
         ),
        "key3" -> Json.arr("alpha", "beta", "gamma", "delta"),
        "key4" -> Json.obj("key41" -> 345, "key42" -> "alpha")
      )

      js.transform(jsonTransformer) must beEqualTo(res)
    }

  }

  "JSON Reads" should {
    "mix reads constraints" in {
      case class User(id: Long, email: String, age: Int)

      implicit val UserReads = (
        (__ \ 'id).read[Long] and
        (__ \ 'email).read( email provided minLength[String](5) ) and
        (__ \ 'age).read( max(55) or min(65) )
      )(User)


      Json.obj( "id" -> 123L, "email" -> "john.doe@blibli.com", "age" -> 50).validate[User] must beEqualTo(JsSuccess(User(123L, "john.doe@blibli.com", 50)))
      Json.obj( "id" -> 123L, "email" -> "john.doe@blibli.com", "age" -> 60).validate[User] must beEqualTo(JsError(ValidationError("validate.error.max", 55)) ++ JsError(ValidationError("validate.error.min", 65)))
      Json.obj( "id" -> 123L, "email" -> "john.doe", "age" -> 60).validate[User] must beEqualTo(JsError(ValidationError("validate.error.email")) ++ JsError(ValidationError("validate.error.max", 55)) ++ JsError(ValidationError("validate.error.min", 65)))
    }
  }
  /*
  "JSON JsMapper 3-fields case class" should {
    case class User2(id: Long, name: String, age: Int)
    implicit val UserFormat2 = JsMapper(
      JsPath \ 'id -> in( of[Long] ),
      JsPath \ 'name -> in( minLength(5) ),
      JsPath \ 'age -> in( max(85) )
    )(User2)(User2.unapply)

    "validate simple case class" in {
      val bobby = User2(1234L, "bobby", 75)
      val js = Json.toJson(bobby)
      js.validate[User2] must equalTo(JsSuccess(bobby))
    }

    "fail validation when type are not respected " in {
      val obj = Json.obj("id" -> 1234L, "name" -> 5, "age" -> "blabla")
      obj.validate[User2] must equalTo(JsError(Seq(
        JsPath \ 'name -> Seq(ValidationError("validate.error.expected.jsstring")), 
        JsPath \ 'age -> Seq(ValidationError("validate.error.expected.jsnumber")))))
    }

    "fail validation when constraints are not respected " in {
      val bob = User2(1234L, "bob", 86)
      val js = Json.toJson(bob)
      // SHOULD BE AT THE END js.validate[User] must equalTo(JsError(js, Json.obj("name" -> JsErrorObj(JsString("bob"), "validate.error.minLength", JsNumber(5)))))
      js.validate[User2] must equalTo(JsError(Seq(
        JsPath \ "name" -> Seq(ValidationError("validate.error.minLength", 5)), 
        JsPath \ "age" -> Seq(ValidationError("validate.error.max", 85)))))
    }

    "fail validation when field missing" in {
      val js = Json.obj("id" -> 1234L, "nick" -> "bob")
      js.validate[User2] must equalTo(
        JsError(Seq(
          JsPath \ "name" -> Seq(ValidationError("validate.error.missing-path"), ValidationError("validate.error.expected.jsstring")),
          JsPath \ "age" -> Seq(ValidationError("validate.error.missing-path"), ValidationError("validate.error.expected.jsnumber"))
        ))
      )
    }


  }

  "JSON JsMapper 3-fields case class with multiple constraints" should {
    case class User3(id: Long, name: String, age: Int)
    implicit val UserFormat3 = JsMapper(
      JsPath \ 'id -> in[Long],
      JsPath \ 'name -> in( minLength(5) or valueEquals[String]("John") ),
      JsPath \ 'age -> in( max(85) and min(15) )
    )(User3)(User3.unapply)

    "validate simple case class" in {
      val bobby = User3(1234L, "bobby", 75)
      val js = Json.toJson(bobby)
      js.validate[User3] must equalTo(JsSuccess(bobby))
    }

    "fail validation when type are not respected " in {
      val obj = Json.obj("id" -> 1234L, "name" -> 5, "age" -> "blabla")
      obj.validate[User3] must equalTo(JsError(Seq(
        JsPath \ 'name -> Seq(ValidationError("validate.error.expected.jsstring")), 
        JsPath \ 'age -> Seq(ValidationError("validate.error.expected.jsnumber")))))
    }

    "fail validation when constraints are NOT respected " in {
      val bob = User3(1234L, "bob", 86)
      val js = Json.toJson(bob)
      // SHOULD BE AT THE END js.validate[User] must equalTo(JsError(js, Json.obj("name" -> JsErrorObj(JsString("bob"), "validate.error.minLength", JsNumber(5)))))
      js.validate[User3] must equalTo(JsError(Seq(
        JsPath \ "name" -> Seq(ValidationError("validate.error.minLength", 5), ValidationError("validate.error.equals", "John")), 
        JsPath \ "age" -> Seq(ValidationError("validate.error.max", 85)))))
    }

    "fail validation when OR constraints are respected " in {
      val bob = User3(1234L, "John", 86)
      val js = Json.toJson(bob)
      // SHOULD BE AT THE END js.validate[User] must equalTo(JsError(js, Json.obj("name" -> JsErrorObj(JsString("bob"), "validate.error.minLength", JsNumber(5)))))
      js.validate[User3] must equalTo(JsError(Seq(
        JsPath \ "age" -> Seq(ValidationError("validate.error.max", 85)))))
    }

    "fail validation when field missing" in {
      val js = Json.obj("id" -> 1234L, "nick" -> "bob")
      js.validate[User3] must equalTo(
        JsError(Seq(
          JsPath \ "name" -> Seq(ValidationError("validate.error.missing-path"), ValidationError("validate.error.expected.jsstring")),
          JsPath \ "age" -> Seq(ValidationError("validate.error.missing-path"), ValidationError("validate.error.expected.jsnumber"))
        )))
    }

    
  }  


  "JSON required constraint" should {
    case class User4(id: Long, name: String, age: Int)
    implicit val UserFormat4 = JsMapper(
      JsPath \ 'id -> in( of[Long] ),
      JsPath \ 'name -> in( required[String] and minLength(5) ),
      JsPath \ 'age -> in( max(85) and min(15) )
    )(User4)(User4.unapply)

   "validate missing field" in {
      val obj = Json.obj("id" -> 1234L, "age" -> "blabla")
      obj.validate[User4] must equalTo(
        JsError(Seq(
          JsPath \ "name" -> Seq(ValidationError("validate.error.missing-path"), ValidationError("validate.error.required"), ValidationError("validate.error.expected.jsstring")),
          JsPath \ "age" -> Seq(ValidationError("validate.error.expected.jsnumber"))
        )))
    }

    "validate failed constraints" in {
      val obj = Json.obj("id" -> 1234L, "name" -> "bob", "age" -> 5)
      obj.validate[User4] must equalTo(
        JsError(Seq(
          JsPath \ "name" -> Seq(ValidationError("validate.error.minLength", 5)),
          JsPath \ "age" -> Seq(ValidationError("validate.error.min", 15))
        )))
    }
  }


  "JSON optional constraint" should {
    case class User5(id: Long, name: String, age: Option[Int])
    implicit val UserFormat5 = JsMapper(
      JsPath \ 'id -> in( of[Long] ),
      JsPath \ 'name -> in( required[String] ),
      JsPath \ 'age -> in( optional[Int] )
    )(User5)(User5.unapply)

    "validate missing optional field" in {
      val obj = Json.obj("id" -> 1234L, "name" -> "bob")
      obj.validate[User5] must equalTo(JsSuccess(User5(1234L, "bob", None)))
    }

    "validate optional field" in {
      val obj = Json.obj("id" -> 1234L, "name" -> "bob", "age" -> 5)
      obj.validate[User5] must equalTo(JsSuccess(User5(1234L, "bob", Some(5))))
    }

     "validate other than optional missing field" in {
      val obj = Json.obj("id" -> 1234L)
      obj.validate[User5] must equalTo(
        JsError(Seq(
          JsPath \ "name" -> Seq(ValidationError("validate.error.missing-path"), ValidationError("validate.error.required"), ValidationError("validate.error.expected.jsstring"))
        )))
    }
  }

  "JSON email constraint" should {
    val myFormat = JsTupler(
      JsPath \ 'email -> in(email)
    )

    "validate email" in {
      val obj = Json.obj("email" -> "pascal.voitot@zenexity.com")
      obj.validate[String](myFormat) must equalTo(JsSuccess("pascal.voitot@zenexity.com"))
    }

    "refuse email" in {
      val obj = Json.obj("email" -> "pascal.voitotnexity.com")
      obj.validate[String](myFormat) must equalTo(
        JsError(Seq(JsPath \ "email" -> Seq(ValidationError("validate.error.email"))))
      )
    }
  }    


  "JSON JsValidator 3-fields" should {
    implicit val myFormat = JsTupler(
      JsPath \ 'id -> in[Long],
      JsPath \ 'name -> in( required[String] ),
      JsPath \ 'password -> in( required[String] ) ~ out( pruned[String] )
    )

    "validate json to tuple" in {
      val obj = Json.obj("id" -> 1234L, "name" -> "bob", "password" -> "password")
      obj.validate[(Long, String, String)] must equalTo(JsSuccess((1234L, "bob", "password")))
    }

    "rewrite tuple to json" in {
      val obj = Json.obj("id" -> 1234L, "name" -> "bob")

      toJson((1234L, "bob", "password")) must equalTo(obj)
    }
  }*/

}
