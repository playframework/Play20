package play.core


object Execution {

  lazy val playInternalContext: scala.concurrent.ExecutionContext =
    scala.concurrent.ExecutionContext.Implicits.global: scala.concurrent.ExecutionContext //FIXME use a proper ThreadPool for Play from Conf

}
