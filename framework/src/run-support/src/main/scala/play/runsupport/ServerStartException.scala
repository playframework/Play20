/*
 * Copyright (C) 2009-2017 Lightbend Inc. <https://www.lightbend.com>
 */
package play.runsupport

class ServerStartException(underlying: Throwable) extends IllegalStateException(underlying) {
  override def getMessage = underlying.getMessage
}
