/*
 * Copyright (C) 2009-2016 Lightbend Inc. <https://www.lightbend.com>
 */
package play.api.libs.iteratee

import play.api.libs.iteratee.Execution.Implicits.{ defaultExecutionContext => dec }
import play.api.libs.iteratee.internal.{ executeIteratee, executeFuture }
import scala.collection.TraversableLike
import scala.collection.generic.CanBuildFrom
import scala.concurrent.{ ExecutionContext, Future }
import scala.language.higherKinds

/**
 * Combines the roles of an Iteratee[From] and a Enumerator[To].  This allows adapting of streams to that modify input
 * produced by an Enumerator, or to be consumed by a Iteratee.
 */
trait Enumeratee[From, To] {
  parent =>

  /**
   * Create a new Iteratee that feeds its input, potentially modifying it along the way, into the inner Iteratee, and
   * produces that Iteratee as its result.
   */
  def applyOn[A](inner: Iteratee[To, A]): Iteratee[From, Iteratee[To, A]]

  /**
   * Alias for `applyOn`
   */
  def apply[A](inner: Iteratee[To, A]): Iteratee[From, Iteratee[To, A]] = applyOn(inner)

  /**
   * Transform the given iteratee into an iteratee that accepts the input type that this enumeratee maps.
   */
  def transform[A](inner: Iteratee[To, A]): Iteratee[From, A] = apply(inner).joinI

  /**
   * Alias for `transform`
   */
  def &>>[A](inner: Iteratee[To, A]): Iteratee[From, A] = transform(inner)

  /**
   * Alias for `apply`
   */
  def &>[A](inner: Iteratee[To, A]): Iteratee[From, Iteratee[To, A]] = apply(inner)

  /**
   * Compose this Enumeratee with another Enumeratee
   */
  def compose[To2](other: Enumeratee[To, To2]): Enumeratee[From, To2] = new Enumeratee[From, To2] {
    def applyOn[A](iteratee: Iteratee[To2, A]) = parent.applyOn(other.applyOn(iteratee)).joinI
  }

  /**
   * Compose this Enumeratee with another Enumeratee
   */
  def ><>[To2](other: Enumeratee[To, To2]): Enumeratee[From, To2] = compose(other)

  /**
   * Compose this Enumeratee with another Enumeratee, concatenating any input left by both Enumeratees when they
   * are done.
   */
  def composeConcat[X](other: Enumeratee[To, To])(implicit p: To => TraversableLike[X, To], bf: CanBuildFrom[To, X, To]): Enumeratee[From, To] = new Enumeratee[From, To] {
    def applyOn[A](iteratee: Iteratee[To, A]) = parent.applyOn(other.applyOn(iteratee).joinConcatI)
  }

  /**
   * Alias for `composeConcat`
   */
  def >+>[X](other: Enumeratee[To, To])(implicit p: To => TraversableLike[X, To], bf: CanBuildFrom[To, X, To]): Enumeratee[From, To] = composeConcat[X](other)

}

/**
 * @define paramEcSingle @param ec The context to execute the supplied function with. The context is prepared on the calling thread before being used.
 * @define paramEcMultiple @param ec The context to execute the supplied functions with. The context is prepared on the calling thread before being used.
 */
object Enumeratee {

  /**
   * An Enumeratee that checks to ensure that the passed in Iteratee is not done before doing any work.
   */
  trait CheckDone[From, To] extends Enumeratee[From, To] {

    protected[this] def continue[A](k: K[To, A]): Iteratee[From, Iteratee[To, A]]

    def applyOn[A](it: Iteratee[To, A]) =
      it.pureFlatFold[From, Iteratee[To, A]] {
        case Step.Cont(k) => continue(k)
        case _ => Done(it)
      }(dec)
  }

  /**
   * An Enuneratee that checks to ensure that the passed in Iteratee is not done, and if it is not done, always
   * continues
   */
  trait ContinueCheckDone[From, To] extends CheckDone[From, To] {
    protected[this] def continue[A](k: K[To, A]) = Cont(step(k))

    protected[this] def step[A](k: K[To, A]): K[From, Iteratee[To, A]]
  }

  trait ForElement[From, To] extends Enumeratee[From, To] {
    /**
     * Pass through [[Input.Empty]] and finish on [[Input.EOF]]
     */
    def forElement[A](k: K[To, A])(f: Input.El[From] => Iteratee[From, Iteratee[To, A]]): K[From, Iteratee[To, A]] = {
      case in @ Input.El(_) => f(in)
      case Input.Empty => this &> k(Input.Empty)
      case Input.EOF => Done(Cont(k), Input.EOF)
    }
  }

  /**
   * Helps with partially applied types for [[Enumeratee]], for more convenient type inference.
   */
  trait EnumerateeProviderBase[From] {
    protected[this]type Arg[_]

    protected[this]type Result[To] = Enumeratee[From, To]
  }

  /**
   * Provides an [[Enumeratee]] given a single argument.
   */
  trait EnumerateeProvider[From] extends EnumerateeProviderBase[From] {
    def apply[To](a: Arg[To]): Result[To]
  }

  /**
   * Provides an [[Enumeratee]] given an argument and an [[ExecutionContext]]
   */
  trait EnumerateeProviderEc[From] extends EnumerateeProviderBase[From] {
    def apply[To](a: Arg[To])(implicit ec: ExecutionContext): Result[To]
  }

  /**
   * flatten a [[scala.concurrent.Future]] of [[play.api.libs.iteratee.Enumeratee]]] into an Enumeratee
   *
   * @param futureOfEnumeratee a future of enumeratee
   */
  def flatten[From, To](futureOfEnumeratee: Future[Enumeratee[From, To]]): Enumeratee[From, To] = new Enumeratee[From, To] {
    def applyOn[A](it: Iteratee[To, A]) = Iteratee.flatten(futureOfEnumeratee.map(_.applyOn(it))(dec))
  }

  /**
   * Create an Enumeratee that zips two Iteratees together.
   *
   * Each input gets passed to each Iteratee, and the result is a tuple of both of their results.
   *
   * If either Iteratee encounters an error, the result will be an error.
   *
   * The Enumeratee will continue consuming input until both inner Iteratees are done.  If one inner Iteratee finishes
   * before the other, the result of that Iteratee is held, and the one continues by itself, until it too is finished.
   */
  def zip[E, A, B](inner1: Iteratee[E, A], inner2: Iteratee[E, B]): Iteratee[E, (A, B)] = zipWith(inner1, inner2)((_, _))(dec)

  /**
   * Create an Enumeratee that zips two Iteratees together, using the passed in zipper function to combine the results
   * of the two.
   *
   * @param inner1 The first Iteratee to combine.
   * @param inner2 The second Iteratee to combine.
   * @param zipper Used to combine the results of each Iteratee.
   * $paramEcSingle
   */
  def zipWith[E, A, B, C](inner1: Iteratee[E, A], inner2: Iteratee[E, B])(zipper: (A, B) => C)(implicit ec: ExecutionContext): Iteratee[E, C] = {
    val pec = ec.prepare()
    import Execution.Implicits.{ defaultExecutionContext => ec } // Shadow ec to make this the only implicit EC in scope

    def getNext(it1: Iteratee[E, A], it2: Iteratee[E, B]): Iteratee[E, C] = {
      val eventuallyIter =
        for (
          (a1, it1_) <- getInside(it1);
          (a2, it2_) <- getInside(it2)
        ) yield checkDone(a1, a2) match {
          case Left((msg, in)) => Error(msg, in)
          case Right(None) => Cont(step(it1_, it2_))
          case Right(Some(Left(Left(a)))) => it2_.map(b => zipper(a, b))(pec)
          case Right(Some(Left(Right(b)))) => it1_.map(a => zipper(a, b))(pec)
          case Right(Some(Right(((a, b), e)))) => executeIteratee(Done(zipper(a, b), e))(pec)
        }

      Iteratee.flatten(eventuallyIter)
    }

    def step(it1: Iteratee[E, A], it2: Iteratee[E, B])(in: Input[E]) = {
      Iteratee.flatten(
        for (
          it1_ <- it1.feed(in);
          it2_ <- it2.feed(in)
        ) yield getNext(it1_, it2_))

    }

    def getInside[T](it: Iteratee[E, T]): Future[(Option[Either[(String, Input[E]), (T, Input[E])]], Iteratee[E, T])] = {
      it.pureFold {
        case Step.Done(a, e) => Some(Right((a, e)))
        case Step.Cont(k) => None
        case Step.Error(msg, e) => Some(Left((msg, e)))
      }(dec).map(r => (r, it))(dec)

    }

    def checkDone(x: Option[Either[(String, Input[E]), (A, Input[E])]], y: Option[Either[(String, Input[E]), (B, Input[E])]]): Either[(String, Input[E]), Option[Either[Either[A, B], ((A, B), Input[E])]]] =
      (x, y) match {
        case (Some(Right((a, e1))), Some(Right((b, e2)))) => Right(Some(Right(((a, b), e1 /* FIXME: should calculate smalled here*/ ))))
        case (Some(Left((msg, e))), _) => Left((msg, e))
        case (_, Some(Left((msg, e)))) => Left((msg, e))
        case (Some(Right((a, _))), None) => Right(Some(Left(Left(a))))
        case (None, Some(Right((b, _)))) => Right(Some(Left(Right(b))))
        case (None, None) => Right(None)

      }
    getNext(inner1, inner2)

  }

  /**
   * Create an Enumeratee that transforms its input using the given function.
   *
   * This is like the `map` function, except that it allows the Enumeratee to, for example, send EOF to the inner
   * iteratee before EOF is encountered.
   */
  def mapInput[From] = new EnumerateeProviderEc[From] {
    type Arg[To] = Input[From] => Input[To]

    def apply[To](f: Arg[To])(implicit ec: ExecutionContext) = new ContinueCheckDone[From, To] {
      val pec = ec.prepare()

      protected[this] def step[A](k: K[To, A]) = {
        case Input.EOF => Done(Cont(k), Input.EOF)
        case in => this &> Iteratee.flatten(Future(f(in))(pec).map(k)(dec))
      }
    }
  }

  /**
   * Create an enumeratee that transforms its input into a sequence of inputs for the target iteratee.
   */
  def mapConcatInput[From] = new EnumerateeProviderEc[From] {
    type Arg[To] = From => Seq[Input[To]]

    def apply[To](f: Arg[To])(implicit ec: ExecutionContext): Result[To] = mapFlatten[From](in => Enumerator.enumerateSeq2(f(in)))(ec)
  }

  /**
   * Create an Enumeratee that transforms its input elements into a sequence of input elements for the target Iteratee.
   */
  def mapConcat[From] = new EnumerateeProviderEc[From] {
    type Arg[To] = From => Seq[To]

    def apply[To](f: Arg[To])(implicit ec: ExecutionContext): Result[To] = mapFlatten[From](in => Enumerator.enumerateSeq1(f(in)))(ec)
  }

  /**
   * Create an Enumeratee that transforms its input elements into an Enumerator that is fed into the target Iteratee.
   */
  def mapFlatten[From] = new EnumerateeProviderEc[From] {
    type Arg[To] = From => Enumerator[To]

    def apply[To](f: Arg[To])(implicit ec: ExecutionContext): Result[To] = new ContinueCheckDone[From, To] with ForElement[From, To] {
      val pec = ec.prepare()

      def step[A](k: K[To, A]) = forElement(k) { in =>
        this &> Iteratee.flatten(Future(f(in.e))(pec).flatMap(_(Cont(k)))(dec))
      }
    }
  }

  /**
   * Create an Enumeratee that transforms its input into an Enumerator that is fed into the target Iteratee.
   */
  def mapInputFlatten[From] = new EnumerateeProviderEc[From] {
    type Arg[To] = Input[From] => Enumerator[To]

    def apply[To](f: Arg[To])(implicit ec: ExecutionContext): Result[To] = new ContinueCheckDone[From, To] {
      val pec = ec.prepare()

      protected[this] def step[A](k: K[To, A]) = in =>
        this &> Iteratee.flatten(Future(f(in))(pec).flatMap(_(Cont(k)))(dec))
    }
  }

  /**
   * Like `mapInput`, but allows the map function to asynchronously return the mapped input.
   */
  def mapInputM[From] = new EnumerateeProviderEc[From] {
    type Arg[To] = Input[From] => Future[Input[To]]

    def apply[To](f: Arg[To])(implicit ec: ExecutionContext): Result[To] = new ContinueCheckDone[From, To] {
      val pec = ec.prepare()

      def step[A](k: K[To, A]) = {
        case Input.EOF => Done(Cont(k), Input.EOF)
        case in => this &> Iteratee.flatten(executeFuture(f(in))(pec).map(k)(dec))
      }
    }
  }

  /**
   * Like `map`, but allows the map function to asynchronously return the mapped element.
   */
  def mapM[E] = new EnumerateeProviderEc[E] {
    type Arg[NE] = E => Future[NE]

    def apply[NE](f: Arg[NE])(implicit ec: ExecutionContext): Result[NE] = mapInputM[E] {
      case Input.El(e) => f(e).map(Input.El(_))(dec)
      case Input.Empty => Future.successful(Input.Empty)
      case Input.EOF => Future.successful(Input.EOF)
    }(ec)
  }

  /**
   * Create an Enumeratee which transforms its input using a given function
   */
  def map[E] = new EnumerateeProviderEc[E] {
    type Arg[NE] = E => NE

    def apply[NE](f: Arg[NE])(implicit ec: ExecutionContext): Result[NE] = mapInput[E](_.map(f))(ec)
  }

  /**
   * Create an Enumeratee that will take `count` input elements to pass to the target Iteratee, and then be done
   *
   * @param count The number of elements to take
   */
  def take[E](count: Int): Enumeratee[E, E] = new CheckDone[E, E] with ForElement[E, E] {
    def continue[A](k: K[E, A]) = if (count <= 0) Done(Cont(k)) else Cont(forElement(k)(take(count - 1) &> k(_)))
  }

  /**
   * A partially-applied function returned by the `scanLeft` method.
   */
  trait ScanLeft[From] {
    def apply[To](seed: To)(f: (To, From) => To): Enumeratee[From, To]
  }

  def scanLeft[From] = new ScanLeft[From] {
    s =>
    def apply[To](seed: To)(f: (To, From) => To): Enumeratee[From, To] = new ContinueCheckDone[From, To] with ForElement[From, To] {
      def step[A](k: K[To, A]) = forElement(k) { in =>
        val next = f(seed, in.e)
        s(next)(f) &> k(Input.El(next))
      }
    }
  }

  /**
   * Create an Enumeratee that groups input using the given Iteratee.
   *
   * This will apply that Iteratee over and over, passing the result each time as the input for the target Iteratee,
   * until EOF is reached.  For example, let's say you had an Iteratee that took a stream of characters and parsed a
   * single line:
   *
   * {{{
   * def takeLine = for {
   *   line <- Enumeratee.takeWhile[Char](_ != '\n') &>> Iteratee.getChunks
   *   _    <- Enumeratee.take(1) &>> Iteratee.ignore[Char]
   * } yield line.mkString
   * }}}
   *
   * This could be used to build an Enumeratee that converts a stream of characters into a stream of lines:
   *
   * {{{
   * def asLines = Enumeratee.grouped(takeLine)
   * }}}
   */
  def grouped[From] = new EnumerateeProvider[From] {
    type Arg[To] = Iteratee[From, To]

    def apply[To](folder: Arg[To]): Result[To] = new ContinueCheckDone[From, To] {
      protected[this] def step[A](k: K[To, A]) = stepWithFolder(folder)(k)

      protected[this] def stepWithFolder[A](f: Iteratee[From, To])(k: K[To, A]): K[From, Iteratee[To, A]] = {
        case Input.EOF => Iteratee.flatten(f.run.map(c => Done(k(Input.El(c)), Input.EOF: Input[From]))(dec))
        case in =>
          Iteratee.flatten(f.feed(in)).pureFlatFold {
            case Step.Done(a, left) => new CheckDone[From, To] {
              def continue[A](k: K[To, A]) =
                left match {
                  case Input.El(_) => step(k)(left)
                  case _ => Cont(step(k))
                }
            } &> k(Input.El(a))
            case Step.Cont(kF) => Cont(stepWithFolder(Cont(kF))(k))
            case Step.Error(msg, e) => Error(msg, in)
          }(dec)
      }
    }
  }

  /**
   * Create an Enumeratee that filters the inputs using the given predicate
   *
   * @param predicate A function to filter the input elements.
   * $paramEcSingle
   */
  def filter[E](predicate: E => Boolean)(implicit ec: ExecutionContext): Enumeratee[E, E] = new ContinueCheckDone[E, E] with ForElement[E, E] {
    val pec = ec.prepare()

    protected[this] def step[A](k: K[E, A]) = forElement(k) { in =>
      Iteratee.flatten(Future(predicate(in.e))(pec).map(if (_) this &> k(in) else Cont(step(k)))(dec))
    }
  }

  /**
   * Create an Enumeratee that filters the inputs using the negation of the given predicate
   *
   * @param predicate A function to filter the input elements.
   * $paramEcSingle
   */
  def filterNot[E](predicate: E => Boolean)(implicit ec: ExecutionContext): Enumeratee[E, E] = filter[E](e => !predicate(e))(ec)

  /**
   * Create an Enumeratee that both filters and transforms its input. The input is transformed by the given
   * PartialFunction. If the PartialFunction isn't defined for an input element then that element is discarded.
   */
  def collect[From] = new EnumerateeProviderEc[From] {
    type Arg[To] = PartialFunction[From, To]

    def apply[To](transformer: Arg[To])(implicit ec: ExecutionContext): Result[To] = new ContinueCheckDone[From, To] with ForElement[From, To] {
      val pec = ec.prepare()

      protected[this] def step[A](k: K[To, A]) = forElement(k) { in =>
        Iteratee.flatten(Future {
          if (transformer.isDefinedAt(in.e)) {
            this &> k(Input.El(transformer(in.e)))
          } else {
            Cont(step(k))
          }
        }(pec))
      }
    }
  }

  def drop[E](count: Int): Enumeratee[E, E] = new ContinueCheckDone[E, E] {
    protected[this] def step[A](k: K[E, A]) = stepWithCount(count)(k)

    private[this] def stepWithCount[A](count: Int)(k: K[E, A]): K[E, Iteratee[E, A]] = {

      case in @ Input.El(_) if count > 0 => Cont(stepWithCount(count - 1)(k))

      case Input.Empty if count > 0 => Cont(step(k))

      case Input.EOF => Done(Cont(k), Input.EOF)

      case in => passAlong &> k(in)

    }
  }

  /**
   * Create an Enumeratee that drops input until a predicate is satisfied.
   *
   * @param p A predicate to test the input with.
   * $paramEcSingle
   */
  def dropWhile[E](p: E => Boolean)(implicit ec: ExecutionContext): Enumeratee[E, E] = {
    val pec = ec.prepare()
    new ContinueCheckDone[E, E] {

      protected[this] def step[A](k: K[E, A]) = {

        case in @ Input.El(e) => Iteratee.flatten(Future(p(e))(pec).map {
          b => if (b) Cont(step(k)) else passAlong &> k(in)
        }(dec))

        case Input.Empty => Cont(step(k))

        case Input.EOF => Done(Cont(k), Input.EOF)

      }

    }
  }

  /**
   * Create an Enumeratee that passes input through while a predicate is satisfied. Once the predicate
   * fails, no more input is passed through.
   *
   * @param p A predicate to test the input with.
   * $paramEcSingle
   */
  def takeWhile[E](p: E => Boolean)(implicit ec: ExecutionContext): Enumeratee[E, E] = new ContinueCheckDone[E, E] with ForElement[E, E] {
    val pec = ec.prepare()

    protected[this] def step[A](k: K[E, A]) = forElement(k) { in =>
      Iteratee.flatten(Future(p(in.e))(pec).map(if (_) this &> k(in) else Done(Cont(k), in))(dec))
    }
  }

  /**
   * Create an Enumeratee that passes input through until a predicate is satisfied. Once the predicate
   * is satisfied, no more input is passed through.
   *
   * @param p A predicate to test the input with.
   * $paramEcSingle
   */
  def breakE[E](p: E => Boolean)(implicit ec: ExecutionContext): Enumeratee[E, E] = new ContinueCheckDone[E, E] with ForElement[E, E] {
    val pec = ec.prepare()

    protected[this] def step[A](k: K[E, A]) = forElement(k) { in =>
      Iteratee.flatten(Future(p(in.e))(pec).map(if (_) Done(Cont(k), in) else this &> k(in))(dec))
    }
  }

  /**
   * An enumeratee that passes all input through until EOF is reached, redeeming the final iteratee with EOF as the
   * left over input.
   */
  def passAlong[M] = new ContinueCheckDone[M, M] with ForElement[M, M] {
    protected[this] def step[A](k: K[M, A]) = forElement(k)(this &> k(_))
  }

  def heading[E](es: Enumerator[E]): Enumeratee[E, E] = new Enumeratee[E, E] {

    def applyOn[A](it: Iteratee[E, A]) = passAlong &> Iteratee.flatten(es(it))

  }

  def trailing[M](es: Enumerator[M]) = new ContinueCheckDone[M, M] {
    protected[this] def step[A](k: K[M, A]) = {
      case Input.EOF => Iteratee.flatten((es |>> Cont(k)).map(Done(_, Input.EOF: Input[M]))(dec))
      case in => this &> k(in)
    }
  }

  /**
   * Create an Enumeratee that performs an action when its Iteratee is done.
   *
   * @param action The action to perform.
   * $paramEcSingle
   */
  def onIterateeDone[E](action: () => Unit)(implicit ec: ExecutionContext): Enumeratee[E, E] = new Enumeratee[E, E] {
    val pec = ec.prepare()

    def applyOn[A](iteratee: Iteratee[E, A]) = (passAlong &> iteratee).map(_.map { a => action(); a }(pec))(dec)
  }

  /**
   * Create an Enumeratee that performs an action on EOF.
   *
   * @param action The action to perform.
   * $paramEcSingle
   */
  def onEOF[E](action: () => Unit)(implicit ec: ExecutionContext): Enumeratee[E, E] = new ContinueCheckDone[E, E] {
    val pec = ec.prepare()

    protected[this] def step[A](k: K[E, A]) = {
      case Input.EOF => Iteratee.flatten(Future(action())(pec).map(_ => Done(Cont(k), Input.EOF: Input[E]))(dec))
      case in => this &> k(in)
    }
  }

  /**
   * Create an Enumeratee that recovers an iteratee in Error state.
   *
   * This will ignore the input that caused the iteratee's error state
   * and use the previous state of the iteratee to handle the next input.
   *
   * {{{f
   *  Enumerator(0, 2, 4) &> Enumeratee.recover { (error, input) =>
   *    Logger.error(f"oops failure occurred with input: \$input", error)
   *  } &> Enumeratee.map { i =>
   *    8 / i
   *  } |>>> Iteratee.getChunks // => List(4, 2)
   * }}}
   *
   * @param f Called when an error occurs with the cause of the error and the input associated with the error.
   * $paramEcSingle
   */
  def recover[E](f: (Throwable, Input[E]) => Unit = (_: Throwable, _: Input[E]) => ())(implicit ec: ExecutionContext): Enumeratee[E, E] = new Enumeratee[E, E] {
    self =>

    val pec = ec.prepare()

    def applyOn[A](it: Iteratee[E, A]) = Cont {
      case Input.EOF => Done(it)
      case in =>
        val enumeratee = new CheckDone[E, E] {
          def continue[A](k: K[E, A]) = new CheckDone[E, E] {
            def continue[A](k: K[E, A]) = self &> Cont(k)
          } &> k(in)
        }
        val next = (enumeratee &> it).unflatten.map(_.it)(dec).recover {
          case e =>
            f(e, in)
            this &> it
        }(pec)
        Iteratee.flatten(next)
    }
  }

}
