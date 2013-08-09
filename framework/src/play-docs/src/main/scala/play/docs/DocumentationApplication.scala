package play.docs

import java.io.File
import play.api.mvc._
import play.api._
import play.core._

/**
 * Provides a very simple application that renders Play documentation.
 */
case class DocumentationApplication(projectPath: File, sbtDocLink: SBTDocLink) extends ApplicationProvider {

  val application = new Application with WithDefaultConfiguration {
    def path = projectPath
    def classloader = this.getClass.getClassLoader
    def sources = None
    def mode = Mode.Dev
    def global = new GlobalSettings() {}
    def plugins = Nil
    override lazy val routes = None
  }

  Play.start(application)

  override def path = projectPath
  override def get = Right(application)
  override def handleWebCommand(request: RequestHeader) =
    sbtDocLink.maybeHandleDocRequest(request).asInstanceOf[Option[SimpleResult]].orElse(
      Some(Results.Redirect("/@documentation"))
    )
}
