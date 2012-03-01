package play.api.libs.json

import org.specs2.mutable._
import play.api.libs.json._
import play.api.libs.json.Json._
import play.api.libs.json.Generic._

import scala.util.control.Exception._
import java.text.ParseException

object JsonSpec extends Specification {

  case class User(id: Long, name: String, friends: List[User])

  implicit object UserFormat extends Format[User] {
    def reads(json: JsValue): User = User(
      (json \ "id").as[Long],
      (json \ "name").as[String],
      (json \ "friends").asOpt[List[User]].getOrElse(List()))
    def writes(u: User): JsValue = JsObject(List(
      "id" -> JsNumber(u.id),
      "name" -> JsString(u.name),
      "friends" -> JsArray(u.friends.map(fr => JsObject(List("id" -> JsNumber(fr.id), "name" -> JsString(fr.name)))))))
  }

  case class Car(id: Long, models: Map[String, String])

  implicit val CarFormat:Format[Car] = productFormat2("id", "models")(Car)(Car.unapply)

  import java.util.Date
  case class Post(body: String, created_at: Option[Date])

  import java.text.SimpleDateFormat
  val dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'" // Iso8601 format (forgot timezone stuff)
  val dateParser = new SimpleDateFormat(dateFormat)

  // Try parsing date from iso8601 format
  implicit object DateFormat extends Reads[Date] {
    def reads(json: JsValue): Date = json match {
        // Need to throw a RuntimeException, ParseException beeing out of scope of asOpt
        case JsString(s) => catching(classOf[ParseException]).opt(dateParser.parse(s)).getOrElse(throw new RuntimeException("Parse exception"))
        case _ => throw new RuntimeException("Parse exception")
    }
  }

  implicit object PostFormat extends Format[Post] {
    def reads(json: JsValue): Post = Post(
      (json \ "body").as[String],
      (json \ "created_at").asOpt[Date])
    def writes(p: Post): JsValue = JsObject(List(
      "body" -> JsString(p.body))) // Don't care about creating created_at or not here
  }

  "JSON" should {
    "serialize and desarialize maps properly" in {
      val c = Car(1, Map("ford" -> "1954 model"))
      val jsonCar = toJson(c)
      jsonCar.as[Car] must equalTo(c)
    }
    "serialize and deserialize" in {
      val luigi = User(1, "Luigi", List())
      val kinopio = User(2, "Kinopio", List())
      val yoshi = User(3, "Yoshi", List())
      val mario = User(0, "Mario", List(luigi, kinopio, yoshi))
      val jsonMario = toJson(mario)
      jsonMario.as[User] must equalTo(mario)
      (jsonMario \\ "name") must equalTo(Seq(JsString("Mario"), JsString("Luigi"), JsString("Kinopio"), JsString("Yoshi")))
    }
    "Complete JSON should create full Post object" in {
      val postJson = """{"body": "foobar", "created_at": "2011-04-22T13:33:48Z"}"""
      val expectedPost = Post("foobar", Some(dateParser.parse("2011-04-22T13:33:48Z")))
      val resultPost = Json.parse(postJson).as[Post]
      resultPost must equalTo(expectedPost)
    }
    "Optional parameters in JSON should generate post w/o date" in {
      val postJson = """{"body": "foobar"}"""
      val expectedPost = Post("foobar", None)
      val resultPost = Json.parse(postJson).as[Post]
      resultPost must equalTo(expectedPost)
    }
    "Invalid parameters shoud be ignored" in {
      val postJson = """{"body": "foobar", "created_at":null}"""
      val expectedPost = Post("foobar", None)
      val resultPost = Json.parse(postJson).as[Post]
      resultPost must equalTo(expectedPost)
    }

    "Map[String,String] should be turned into JsValue" in {
      val f = toJson(Map("k"->"v"))
      f.toString must equalTo("{\"k\":\"v\"}")
    }

    "Can parse recursive object" in {
      val recursiveJson = """{"foo": {"foo":["bar"]}, "bar": {"foo":["bar"]}}"""
      val expectedJson = JsObject(List(
        "foo" -> JsObject(List(
          "foo" -> JsArray(List[JsValue](JsString("bar")))
          )),
        "bar" -> JsObject(List(
          "foo" -> JsArray(List[JsValue](JsString("bar")))
          ))
        ))
      val resultJson = Json.parse(recursiveJson)
      resultJson must equalTo(expectedJson)

    }
    "Can parse null values in Object" in {
      val postJson = """{"foo": null}"""
      val parsedJson = Json.parse(postJson)
      val expectedJson = JsObject(List("foo" -> JsNull))
      parsedJson must equalTo(expectedJson)
    }
    "Can parse null values in Array" in {
      val postJson = """[null]"""
      val parsedJson = Json.parse(postJson)
      val expectedJson = JsArray(List(JsNull))
      parsedJson must equalTo(expectedJson)
    }
  }

}

object JsonModifierSpec extends Specification {
  val globalJson = JsObject(
    List(
      "title" -> JsString("Acme"),
      "author" -> JsObject(
        List(
          "firstname" -> JsString("Bugs"),
          "lastname" -> JsString("Bunny")
          )
        ),
      "tags" -> JsArray(
        List[JsValue](
          JsString("Awesome article"),
          JsString("Must read"),
          JsString("Playframework"),
          JsString("Rocks")
          )
        )
      )
    )
  "JsonModifier" should {
    "JsonLookup can get a single item" in {
      globalJson.get(ObjectAccessor("title")) must equalTo(JsString("Acme"))
    }
    "JsonLookup can look in depth for an item" in {
      globalJson.get(ObjectAccessor("author") \ "firstname") must
        equalTo(JsString("Bugs"))
    }
    "JsonLookup can look in an array" in {
      globalJson.get(ObjectAccessor("tags") * 2) must equalTo(JsString("Playframework"))
    }

    "JsonModifier can modify a single item" in {
      globalJson.replace(ObjectAccessor("title"), JsString("Acme more")) must
        equalTo(
        JsObject(
          List(
            "title" -> JsString("Acme more"),
            "author" -> JsObject(
              List(
                "firstname" -> JsString("Bugs"),
                "lastname" -> JsString("Bunny")
                )
              ),
            "tags" -> JsArray(
              List[JsValue](
                JsString("Awesome article"),
                JsString("Must read"),
                JsString("Playframework"),
                JsString("Rocks")
                )
              )
            )
          )
        )
    }

    "JsonModifier can modify an object item" in {
      globalJson.replace(ObjectAccessor("author"), JsString("Bugs bunny")) must
        equalTo(
        JsObject(
          List(
            "title" -> JsString("Acme"),
            "author" -> JsString("Bugs bunny"),
            "tags" -> JsArray(
              List[JsValue](
                JsString("Awesome article"),
                JsString("Must read"),
                JsString("Playframework"),
                JsString("Rocks")
                )
              )
            )
          )
        )
    }

    "JsonModifier can modify an array item" in {
      globalJson.replace(ObjectAccessor("tags") * 0, JsString("Really Awesome article")) must
        equalTo(
        JsObject(
          List(
            "title" -> JsString("Acme"),
            "author" -> JsObject(
              List(
                "firstname" -> JsString("Bugs"),
                "lastname" -> JsString("Bunny")
                )
              ),
            "tags" -> JsArray(
              List[JsValue](
                JsString("Really Awesome article"),
                JsString("Must read"),
                JsString("Playframework"),
                JsString("Rocks")
                )
              )
            )
          )
        )
    }

    "JsonModifier can use callbacks" in {
      globalJson.replace(ObjectAccessor("title"), ((old: JsValue) => old match {
        case JsString(content) => JsString(content.toUpperCase)
        case _ => JsUndefined("not found")
        })
      ) must
        equalTo(
        JsObject(
          List(
            "title" -> JsString("ACME"),
            "author" -> JsObject(
              List(
                "firstname" -> JsString("Bugs"),
                "lastname" -> JsString("Bunny")
                )
              ),
            "tags" -> JsArray(
              List[JsValue](
                JsString("Awesome article"),
                JsString("Must read"),
                JsString("Playframework"),
                JsString("Rocks")
                )
              )
            )
          )
        )
    }

    "JsonModifier can use callbacks and modify again inside" in {
      globalJson.replace(ObjectAccessor("tags"), ((old: JsValue) => old match {
        case o: JsArray => o.replace(
            ArrayAccessor(0), 
            JsString("First")
          ).replace(
            ArrayAccessor(1), 
            JsString("Second"))
        case _ => JsUndefined("not found")
        })
      ) must
        equalTo(
        JsObject(
          List(
            "title" -> JsString("Acme"),
            "author" -> JsObject(
              List(
                "firstname" -> JsString("Bugs"),
                "lastname" -> JsString("Bunny")
                )
              ),
            "tags" -> JsArray(
              List[JsValue](
                JsString("First"),
                JsString("Second"),
                JsString("Playframework"),
                JsString("Rocks")
                )
              )
            )
          )
        )
    }
  }
}

