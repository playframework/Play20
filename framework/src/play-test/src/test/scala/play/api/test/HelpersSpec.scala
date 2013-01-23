package play.api.test

import play.api.test._
import play.api.test.Helpers._
import play.api.mvc._
import play.api.mvc.Results._
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Future

import org.specs2.mutable._

class HelpersSpec extends Specification {

  "inMemoryDatabase" should {

    "change database with a name argument" in {
      val inMemoryDatabaseConfiguration = inMemoryDatabase("test")
      inMemoryDatabaseConfiguration.get("db.test.driver") must beSome("org.h2.Driver")
      inMemoryDatabaseConfiguration.get("db.test.url") must beSome.which { url =>
        url.startsWith("jdbc:h2:mem:play-test-")
      }
    }

    "add options" in {
      val inMemoryDatabaseConfiguration = inMemoryDatabase("test", Map("MODE" -> "PostgreSQL", "DB_CLOSE_DELAY" -> "-1"))
      inMemoryDatabaseConfiguration.get("db.test.driver") must beSome("org.h2.Driver")
      inMemoryDatabaseConfiguration.get("db.test.url") must beSome.which { url =>
        """^jdbc:h2:mem:play-test([0-9-]+);MODE=PostgreSQL;DB_CLOSE_DELAY=-1$""".r.findFirstIn(url).isDefined
      }
    }
  }

  "contentAsString" should {

    "extract the content from Result as String" in {
      contentAsString(Ok("abc")) must_== "abc"
    }

  }

  "contentAsBytes" should {

    "extract the content from Result as Bytes" in {
      contentAsBytes(Ok("abc")) must_== Array(97, 98, 99)
    }

    "extract the content from AsyncResult as Bytes" in {
      contentAsBytes(AsyncResult { Future(Ok("abc")) }) must_== Array(97, 98, 99)
    }

  }


}
