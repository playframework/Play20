package play.api.libs.ws

import org.specs2.mutable._
import org.specs2.mock.Mockito

import com.ning.http.client.{
Response => AHCResponse,
Cookie => AHCCookie,
StringPart => AHCStringPart,
ByteArrayPart => AHCByteArrayPart,
FilePart => AHCFilePart
}
import java.util

object WSSpec extends Specification with Mockito {

  "WS" should {
    "support several query string values for a parameter" in {
      val req = WS.url("http://playframework.com/")
        .withQueryString("foo" -> "foo1", "foo" -> "foo2")
        .prepare("GET").build
      req.getQueryParams.get("foo").contains("foo1") must beTrue
      req.getQueryParams.get("foo").contains("foo2") must beTrue
      req.getQueryParams.get("foo").size must equalTo(2)
    }

    "upload a file with a string part" in {
      val request = WS.url("http://example.com")
        .withHeaders("Content-Type" -> "multipart/form-data")
        .withPart("foo", "bar", "text/plain", "EBCDIC")
        .prepare("POST").build

      val expected = new AHCStringPart("foo", "bar", "EBCDIC")
      val actual = request.getParts.get(0).asInstanceOf[AHCStringPart]

      actual.getName must beEqualTo(expected.getName)
      actual.getValue must beEqualTo(expected.getValue)
      actual.getCharset must beEqualTo(expected.getCharset)
    }

    "upload a file with multiple string parts" in {
      val request = WS.url("http://example.com")
        .withHeaders("Content-Type" -> "multipart/form-data")
        .withStringParts("foo" -> "bar", "baz" -> "quuz")
        .prepare("POST").build()

      val parts = request.getParts

      val one = parts.get(0).asInstanceOf[AHCStringPart]
      one.getName must beEqualTo("foo")
      one.getValue must beEqualTo("bar")

      val two = parts.get(1).asInstanceOf[AHCStringPart]
      two.getName must beEqualTo("baz")
      two.getValue must beEqualTo("quuz")
    }

    "upload a file with multiple file parts" in {
      val request = WS.url("http://example.com")
        .withHeaders("Content-Type" -> "multipart/form-data")
        .withParts("text/plain", "UTF-8",
                   "somefile" -> new java.io.File("somefile.txt"),
                   "otherfile" -> new java.io.File("otherfile.txt"))
        .prepare("POST").build

      val expectedOne = new AHCFilePart("somefile", new java.io.File("somefile.txt"), "text/plain", "UTF-8")
      val expectedTwo = new AHCFilePart("otherfile", new java.io.File("otherfile.txt"), "text/plain", "UTF-8")

      val actualOne = request.getParts.get(0).asInstanceOf[AHCFilePart]
      actualOne.getName must beEqualTo(expectedOne.getName)
      actualOne.getFile must beEqualTo(expectedOne.getFile)
      actualOne.getCharSet must beEqualTo(expectedOne.getCharSet)
      actualOne.getMimeType must beEqualTo(expectedOne.getMimeType)

      val actualTwo = request.getParts.get(1).asInstanceOf[AHCFilePart]
      actualTwo.getName must beEqualTo(expectedTwo.getName)
      actualTwo.getFile must beEqualTo(expectedTwo.getFile)
      actualTwo.getCharSet must beEqualTo(expectedTwo.getCharSet)
      actualTwo.getMimeType must beEqualTo(expectedTwo.getMimeType)
    }

    "upload a file with a file part" in {
      val request = WS.url("http://example.com")
        .withHeaders("Content-Type" -> "multipart/form-data")
        .withPart("name", new java.io.File("somefile.txt"), "text/plain", "UTF-8")
        .prepare("POST").build

      val expected = new AHCFilePart("name", new java.io.File("somefile.txt"), "text/plain", "UTF-8")
      val actual = request.getParts.get(0).asInstanceOf[AHCFilePart]

      actual.getName must beEqualTo(expected.getName)
      actual.getFile must beEqualTo(expected.getFile)
      actual.getCharSet must beEqualTo(expected.getCharSet)
      actual.getMimeType must beEqualTo(expected.getMimeType)
    }

    "upload a file with a byte array part" in {
      val request = WS.url("http://example.com")
        .withHeaders("Content-Type" -> "multipart/form-data")
        .withPart("name", "data".getBytes("UTF-8"), "text/plain", "UTF-8")
        .prepare("POST").build
      val name = "name" // name and filename must be the same
      val expected = new AHCByteArrayPart(name, name, "data".getBytes("UTF-8"), "text/plain", "UTF-8")
      val actual = request.getParts.get(0).asInstanceOf[AHCByteArrayPart]

      actual.getName must beEqualTo(expected.getName)
      actual.getFileName must beEqualTo(expected.getName)
      actual.getData must beEqualTo(expected.getData)
      actual.getCharSet must beEqualTo(expected.getCharSet)
      actual.getMimeType must beEqualTo(expected.getMimeType)
    }

    "upload a file with multiple body parts" in {
      val request = WS.url("http://example.com")
        .withHeaders("Content-Type" -> "multipart/form-data")
        .withStringParts("foo" -> "bar")
        .withStringParts("baz" -> "quuz")
        .withPart("name", new java.io.File("somefile.txt"), "text/plain", "UTF-8")
        .withPart("name", "data".getBytes("UTF-8"), "text/plain", "UTF-8")
        .prepare("POST").build()

      val parts = request.getParts
      parts.get(0) must beAnInstanceOf[AHCStringPart]
      parts.get(1) must beAnInstanceOf[AHCStringPart]
      parts.get(2) must beAnInstanceOf[AHCFilePart]
      parts.get(3) must beAnInstanceOf[AHCByteArrayPart]
    }
  }

  "WS Response" should {
    "get cookies from an AHC response" in {

      val ahcResponse: AHCResponse = mock[AHCResponse]
      val (domain, name, value, path, maxAge, secure) = ("example.com", "someName", "someValue", "/", 1000, false)

      val ahcCookie: AHCCookie = new AHCCookie(domain, name, value, path, maxAge, secure)
      ahcResponse.getCookies returns util.Arrays.asList(ahcCookie)

      val response = Response(ahcResponse)

      val cookies: Seq[Cookie] = response.cookies
      val cookie = cookies(0)

      cookie.domain must ===("example.com")
      cookie.name must beSome("someName")
      cookie.value must beSome("someValue")
      cookie.path must ===("/")
      cookie.maxAge must ===(1000)
      cookie.secure must beFalse
    }

    "get a single cookie from an AHC response" in {
      val ahcResponse: AHCResponse = mock[AHCResponse]
      val (domain, name, value, path, maxAge, secure) = ("example.com", "someName", "someValue", "/", 1000, false)

      val ahcCookie: AHCCookie = new AHCCookie(domain, name, value, path, maxAge, secure)
      ahcResponse.getCookies returns util.Arrays.asList(ahcCookie)

      val response = Response(ahcResponse)

      val optionCookie = response.cookie("someName")
      optionCookie must beSome[Cookie].which {
        cookie =>
          cookie.domain must ===("example.com")
          cookie.name must beSome("someName")
          cookie.value must beSome("someValue")
          cookie.path must ===("/")
          cookie.maxAge must ===(1000)
          cookie.secure must beFalse
      }
    }
  }

}
