package anorm

import java.sql.{ Connection, SQLWarning }

import resource.ManagedResource

/**
 * A result from execution of an SQL query, row data and context
 * (e.g. statement warnings).
 *
 * @constructor create a result with a result set
 * @param resultSet Result set from executed query
 */
final case class SqlQueryResult(
    /** Underlying result set */
    resultSet: ManagedResource[java.sql.ResultSet]) {

  /** Query statement already executed */
  val statement: ManagedResource[java.sql.Statement] =
    resultSet.map(_.getStatement)

  /**
   * Returns statement warning if there is some for this result.
   *
   * {{{
   * val res = SQL("EXEC stored_proc {p}").on("p" -> paramVal).executeQuery()
   * res.statementWarning match {
   *   case Some(warning) =>
   *     warning.printStackTrace()
   *     None
   *
   *   case None =>
   *     // go on with row parsing ...
   *     res.as(scalar[String].singleOpt)
   * }
   * }}}
   */
  def statementWarning: Option[SQLWarning] =
    statement.acquireFor(_.getWarnings).fold[Option[SQLWarning]](
      _.headOption.map(new SQLWarning(_)), Option(_))

  /** Returns stream of row from query result. */
  @deprecated("Use [[fold]] or [[foldWhile]] instead, which manages resources and memory", "2.4")
  def apply()(implicit connection: Connection): Stream[Row] =
    Sql.fold(resultSet)(Stream.empty[Row])((s, r) => (s :+ r) -> true).
      acquireAndGet(identity)

  /**
   * Aggregates over the whole row stream using the specified operator.
   *
   * @param z the start value
   * @param op Aggregate operator
   * @return Either list of failures at left, or aggregated value
   * @see #foldWhile
   */
  def fold[T](z: => T)(op: (T, Row) => T)(implicit connection: Connection): Either[List[Throwable], T] =
    Sql.fold(resultSet)(z)((t, r) => op(t, r) -> true) acquireFor identity

  /**
   * Aggregates over part of or the while row stream,
   * using the specified operator.
   *
   * @param z the start value
   * @param op Aggregate operator. Returns aggregated value along with true if aggregation must process next value, or false to stop with current value.
   * @return Either list of failures at left, or aggregated value
   */
  def foldWhile[T](z: => T)(op: (T, Row) => (T, Boolean))(implicit connection: Connection): Either[List[Throwable], T] =
    Sql.fold(resultSet)(z)((t, r) => op(t, r)) acquireFor identity

  /**
   * Converts this query result as `T`, using parser.
   */
  def as[T](parser: ResultSetParser[T])(implicit connection: Connection): T =
    Sql.as(parser, resultSet)

  // TODO: Scaladoc as `as` equivalent
  def list[A](rowParser: RowParser[A])(implicit connection: Connection): Seq[A] = as(rowParser.*)

  // TODO: Scaladoc as `as` equivalent
  def single[A](rowParser: RowParser[A])(implicit connection: Connection): A =
    as(ResultSetParser.single(rowParser))

  // TODO: Scaladoc as `as` equivalent
  def singleOpt[A](rowParser: RowParser[A])(implicit connection: Connection): Option[A] = as(ResultSetParser.singleOpt(rowParser))

  @deprecated(message = "Use [[as]]", since = "2.3.2")
  def parse[T](parser: ResultSetParser[T])(implicit connection: Connection): T =
    as(parser)

}
