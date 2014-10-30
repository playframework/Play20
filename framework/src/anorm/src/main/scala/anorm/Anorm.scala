/*
 * Copyright (C) 2009-2013 Typesafe Inc. <http://www.typesafe.com>
 */
package anorm

import java.util.{ Date, UUID }
import java.sql.{ Connection, PreparedStatement, ResultSet }

import scala.language.postfixOps
import scala.collection.TraversableOnce
import scala.util.Failure

import resource.{ managed, ManagedResource }

/** Error from processing SQL */
sealed trait SqlRequestError {
  def message: String

  /** Returns error as a failure. */
  def toFailure = Failure(sys.error(message))
}

case class ColumnNotFound(
    column: String, possibilities: List[String]) extends SqlRequestError {

  lazy val message = s"$column not found, available columns : " +
    possibilities.map(_.dropWhile(_ == '.')).mkString(", ")

  override lazy val toString = message
}

case class UnexpectedNullableFound(message: String) extends SqlRequestError
case class SqlMappingError(reason: String) extends SqlRequestError {
  lazy val message = s"SqlMappingError($reason)"
  override lazy val toString = message
}

case class TypeDoesNotMatch(reason: String) extends SqlRequestError {
  lazy val message = s"TypeDoesNotMatch($reason)"
  override lazy val toString = message
}

@deprecated(
  message = "Do not use directly, but consider [[Id]] or [[NotAssigned]].",
  since = "2.3.0")
trait Pk[+ID] extends NotNull {

  def toOption: Option[ID] = this match {
    case Id(x) => Some(x)
    case NotAssigned => None
  }

  def isDefined: Boolean = toOption.isDefined
  def get: ID = toOption.get
  def getOrElse[V >: ID](id: V): V = toOption.getOrElse(id)
  def map[B](f: ID => B) = toOption.map(f)
  def flatMap[B](f: ID => Option[B]) = toOption.flatMap(f)
  def foreach(f: ID => Unit) = toOption.foreach(f)

}

/**
 * Workaround to suppress deprecation warnings within the Play build.
 * Based on https://issues.scala-lang.org/browse/SI-7934
 */
private[anorm] object Pk {
  type Deprecated[A] = Pk[A]
}

case class Id[ID](id: ID) extends Pk.Deprecated[ID] {
  override def toString() = id.toString
}

case object NotAssigned extends Pk.Deprecated[Nothing] {
  override def toString() = "NotAssigned"
}

/**
 * Untyped value wrapper.
 *
 * {{{
 * SQL("UPDATE t SET val = {o}").on('o -> anorm.Object(val))
 * }}}
 */
case class Object(value: Any)

case class MetaDataItem(column: ColumnName, nullable: Boolean, clazz: String)
case class ColumnName(qualified: String, alias: Option[String])

case class MetaData(ms: List[MetaDataItem]) {
  /** Returns meta data for specified column. */
  def get(columnName: String): Option[MetaDataItem] = {
    val key = columnName.toUpperCase
    dictionary2.get(key).orElse(dictionary.get(key)).
      orElse(aliasedDictionary.get(key))
  }

  @deprecated(
    message = "No longer distinction between plain and aliased column",
    since = "2.3.3")
  def getAliased(aliasName: String): Option[MetaDataItem] =
    aliasedDictionary.get(aliasName.toUpperCase)

  private lazy val dictionary: Map[String, MetaDataItem] =
    ms.map(m => m.column.qualified.toUpperCase() -> m).toMap

  private lazy val dictionary2: Map[String, MetaDataItem] =
    ms.map(m => {
      val column = m.column.qualified.split('.').last;
      column.toUpperCase() -> m
    }).toMap

  private lazy val aliasedDictionary: Map[String, MetaDataItem] = {
    ms.flatMap(m => {
      m.column.alias.map(a => Map(a.toUpperCase() -> m)).getOrElse(Map.empty)
    }).toMap
  }

  lazy val columnCount = ms.size

  lazy val availableColumns: List[String] =
    ms.flatMap(i => i.column.qualified :: i.column.alias.toList)

}

@deprecated(message = "Use directly Stream", since = "2.3.3")
object Useful {

  case class Var[T](var content: T)

  @deprecated(message = "Use directly Stream value", since = "2.3.2")
  def unfold1[T, R](init: T)(f: T => Option[(R, T)]): (Stream[R], T) = f(init) match {
    case None => (Stream.Empty, init)
    case Some((r, v)) => (Stream.cons(r, unfold(v)(f)), v)
  }

  def unfold[T, R](init: T)(f: T => Option[(R, T)]): Stream[R] = f(init) match {
    case None => Stream.Empty
    case Some((r, v)) => Stream.cons(r, unfold(v)(f))
  }
}

/**
 * Wrapper to use [[Seq]] as SQL parameter, with custom formatting.
 *
 * {{{
 * SQL("SELECT * FROM t WHERE %s").
 *   on(SeqParameter(Seq("a", "b"), " OR ", Some("cat = ")))
 * // Will execute as:
 * // SELECT * FROM t WHERE cat = 'a' OR cat = 'b'
 * }}}
 */
sealed trait SeqParameter[A] {
  def values: Seq[A]
  def separator: String
  def before: Option[String]
  def after: Option[String]
}

/** SeqParameter factory */
object SeqParameter {
  def apply[A](
    seq: Seq[A], sep: String = ", ",
    pre: String = "", post: String = ""): SeqParameter[A] =
    new SeqParameter[A] {
      val values = seq
      val separator = sep
      val before = Option(pre)
      val after = Option(post)
    }
}

/** Applied named parameter. */
sealed case class NamedParameter(name: String, value: ParameterValue) {
  lazy val tupled: (String, ParameterValue) = (name, value)
}

/** Companion object for applied named parameter. */
object NamedParameter {
  import scala.language.implicitConversions

  /**
   * Conversion to use tuple, with first element being name
   * of parameter as string.
   *
   * {{{
   * val p: Parameter = ("name" -> 1l)
   * }}}
   */
  implicit def string[V](t: (String, V))(implicit c: V => ParameterValue): NamedParameter = NamedParameter(t._1, c(t._2))

  /**
   * Conversion to use tuple,
   * with first element being symbolic name or parameter.
   *
   * {{{
   * val p: Parameter = ('name -> 1l)
   * }}}
   */
  implicit def symbol[V](t: (Symbol, V))(implicit c: V => ParameterValue): NamedParameter = NamedParameter(t._1.name, c(t._2))

}

/** Simple/plain SQL. */
case class SimpleSql[T](sql: SqlQuery, params: Map[String, ParameterValue], defaultParser: RowParser[T]) extends Sql {

  /**
   * Returns query prepared with named parameters.
   *
   * {{{
   * import anorm.toParameterValue
   *
   * val baseSql = SQL("SELECT * FROM table WHERE id = {id}") // one named param
   * val preparedSql = baseSql.withParams("id" -> "value")
   * }}}
   */
  def on(args: NamedParameter*): SimpleSql[T] =
    copy(params = this.params ++ args.map(_.tupled))

  /**
   * Returns query prepared with parameters using initial order
   * of placeholder in statement.
   *
   * {{{
   * import anorm.toParameterValue
   *
   * val baseSql =
   *   SQL("SELECT * FROM table WHERE name = {name} AND lang = {lang}")
   *
   * val preparedSql = baseSql.onParams("1st", "2nd")
   * // 1st param = name, 2nd param = lang
   * }}}
   */
  def onParams(args: ParameterValue*): SimpleSql[T] =
    copy(params = this.params ++ Sql.zipParams(
      sql.paramsInitialOrder, args, Map.empty))

  /** Applies current parser with optionnal list of rows (0..n). */
  @deprecated(
    message = """Use `SQL("...").as(parser.*)`""", since = "2.3.5")
  def list()(implicit connection: Connection): List[T] = as(defaultParser.*)

  /** Applies current parser to exactly on row. */
  @deprecated(
    message = """Use `SQL("...").as(parser.single)`""", since = "2.3.5")
  def single()(implicit connection: Connection): T = as(defaultParser.single)

  /** Applies current parser to one optional row. */
  @deprecated(
    message = """Use `SQL("...").as(parser.singleOpt)`""", since = "2.3.5")
  def singleOpt()(implicit connection: Connection): Option[T] =
    as(defaultParser.singleOpt)

  @deprecated(message = "Use [[preparedStatement]]", since = "2.3.6")
  def getFilledStatement(connection: Connection, getGeneratedKeys: Boolean = false) = {
    val st: (String, Seq[(Int, ParameterValue)]) = Sql.prepareQuery(
      sql.statement, 0, sql.paramsInitialOrder.map(params), Nil)

    val stmt = if (getGeneratedKeys) connection.prepareStatement(st._1, java.sql.Statement.RETURN_GENERATED_KEYS) else connection.prepareStatement(st._1)

    sql.timeout.foreach(stmt.setQueryTimeout(_))

    st._2 foreach { p =>
      val (i, v) = p
      v.set(stmt, i + 1)
    }

    stmt
  }

  def preparedStatement(connection: Connection, getGeneratedKeys: Boolean = false) = managed(getFilledStatement(connection, getGeneratedKeys))

  /**
   * Prepares query with given row parser.
   *
   * {{{
   * import anorm.{ SQL, SqlParser }
   *
   * val res: Int = SQL("SELECT 1").using(SqlParser.scalar[Int]).single
   * // Equivalent to: SQL("SELECT 1").as(SqlParser.scalar[Int].single)
   * }}}
   */
  def using[U](p: RowParser[U]): SimpleSql[U] = copy(sql, params, p)
  // Deprecates with .as ?

  def map[A](f: T => A): SimpleSql[A] =
    copy(defaultParser = defaultParser.map(f))

  def withQueryTimeout(seconds: Option[Int]): SimpleSql[T] =
    copy(sql = sql.withQueryTimeout(seconds))

}

private[anorm] trait Sql extends WithResult {
  @deprecated(message = "Use [[preparedStatement]]", since = "2.3.6")
  def getFilledStatement(connection: Connection, getGeneratedKeys: Boolean = false): PreparedStatement

  def preparedStatement(connection: Connection, getGeneratedKeys: Boolean = false): ManagedResource[PreparedStatement]

  /**
   * Executes this statement as query (see [[executeQuery]]) and returns result.
   */
  protected def resultSet(connection: Connection): ManagedResource[ResultSet] =
    preparedStatement(connection).flatMap(stmt => managed(stmt.executeQuery()))

  /**
   * Executes this SQL statement.
   * @return true if resultset was returned from execution
   * (statement is query), or false if it executed update.
   *
   * {{{
   * val res: Boolean =
   *   SQL"""INSERT INTO Test(a, b) VALUES(${"A"}, ${"B"}""".execute()
   * }}}
   */
  def execute()(implicit connection: Connection): Boolean =
    preparedStatement(connection).acquireAndGet(_.execute())
  // TODO: Safe alternative

  @deprecated(message = "Will be made private, use [[executeUpdate]] or [[executeInsert]]", since = "2.3.2")
  def execute1(getGeneratedKeys: Boolean = false)(implicit connection: Connection): (PreparedStatement, Int) = {
    val statement = getFilledStatement(connection, getGeneratedKeys)
    (statement, statement.executeUpdate())
  }

  /**
   * Executes this SQL as an update statement.
   * @return Count of updated row(s)
   */
  @throws[java.sql.SQLException]("If statement is query not update")
  def executeUpdate()(implicit connection: Connection): Int =
    preparedStatement(connection).acquireAndGet(_.executeUpdate())
  //TODO: Safe alternative

  /**
   * Executes this SQL as an insert statement.
   *
   * @param generatedKeysParser Parser for generated key (default: scalar long)
   * @return Parsed generated keys
   *
   * {{{
   * import anorm.SqlParser.scalar
   *
   * val keys1 = SQL("INSERT INTO Test(x) VALUES ({x})").
   *   on("x" -> "y").executeInsert()
   *
   * val keys2 = SQL("INSERT INTO Test(x) VALUES ({x})").
   *   on("x" -> "y").executeInsert(scalar[String].singleOpt)
   * // ... generated string key
   * }}}
   */
  def executeInsert[A](generatedKeysParser: ResultSetParser[A] = SqlParser.scalar[Long].singleOpt)(implicit connection: Connection): A =
    Sql.asTry(generatedKeysParser, preparedStatement(connection, true).
      flatMap { stmt =>
        stmt.executeUpdate()
        managed(stmt.getGeneratedKeys)
      }).get // TODO: Safe alternative

  /**
   * Executes this SQL query, and returns its result.
   *
   * {{{
   * implicit val conn: Connection = openConnection
   * val res: SqlQueryResult =
   *   SQL("SELECT text_col FROM table WHERE id = {code}").
   *   on("code" -> code).executeQuery()
   * // Check execution context; e.g. res.statementWarning
   * val str = res as scalar[String].single // going with row parsing
   * }}}
   */
  def executeQuery()(implicit connection: Connection): SqlQueryResult =
    SqlQueryResult(resultSet(connection))

}

object Sql { // TODO: Rename to SQL
  import scala.util.{ Success => TrySuccess, Try }

  private[anorm] def withResult[T](res: ManagedResource[ResultSet])(op: Option[Cursor] => T): ManagedResource[T] = res.map(rs => op(Cursor(rs)))

  private[anorm] def asTry[T](parser: ResultSetParser[T], rs: ManagedResource[ResultSet])(implicit connection: Connection): Try[T] = {
    def stream(c: Option[Cursor]): Stream[Row] =
      c.fold(Stream.empty[Row]) { cur => cur.row #:: stream(cur.next) }

    Try(withResult(rs)(c => parser(stream(c))) acquireAndGet identity).
      flatMap(_.fold[Try[T]](_.toFailure, TrySuccess.apply))

  }

  @annotation.tailrec
  private[anorm] def zipParams(ns: Seq[String], vs: Seq[ParameterValue], ps: Map[String, ParameterValue]): Map[String, ParameterValue] = (ns.headOption, vs.headOption) match {
    case (Some(n), Some(v)) =>
      zipParams(ns.tail, vs.tail, ps + (n -> v))
    case _ => ps
  }

  /**
   * Rewrites next format placeholder (%s) in statement, with fragment using
   * [[java.sql.PreparedStatement]] syntax (with one or more '?').
   *
   * @param statement SQL statement (with %s placeholders)
   * @param frag Statement fragment
   * @return Some rewrited statement, or None if there no available placeholder
   *
   * {{{
   * Sql.rewrite("SELECT * FROM Test WHERE cat IN (%s)", "?, ?")
   * // Some("SELECT * FROM Test WHERE cat IN (?, ?)")
   * }}}
   */
  private[anorm] def rewrite(stmt: String, frag: String): Option[String] = {
    val idx = stmt.indexOf("%s")

    if (idx == -1) None
    else {
      val parts = stmt.splitAt(idx)
      Some(parts._1 + frag + parts._2.drop(2))
    }
  }

  @annotation.tailrec
  private[anorm] def prepareQuery(sql: String, i: Int, ps: Seq[ParameterValue], vs: Seq[(Int, ParameterValue)]): (String, Seq[(Int, ParameterValue)]) = {
    ps.headOption match {
      case Some(p) =>
        val st: (String, Int) = p.toSql(sql, i)
        prepareQuery(st._1, st._2, ps.tail, vs :+ (i -> p))
      case _ => (sql, vs)
    }
  }
}
