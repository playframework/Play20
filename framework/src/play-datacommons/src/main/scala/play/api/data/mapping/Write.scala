package play.api.data.mapping

import scala.language.implicitConversions

trait Write[I, +O] {
  def writes(i: I): O

  def map[B](f: O => B) = Write[I, B] {
    f compose (this.writes _)
  }

  def compose[OO >: O, P](w: Write[OO, P]) =
    Write((w.writes _) compose (this.writes _))
}

trait DefaultMonoids {
  import play.api.libs.functional.Monoid

  implicit def mapMonoid = new Monoid[Map[String, Seq[String]]] {
    def append(a1: Map[String, Seq[String]], a2: Map[String, Seq[String]]) = a1 ++ a2
    def identity = Map.empty
  }
}

object Write {

  def apply[I, O](w: I => O): Write[I, O] = new Write[I, O] {
    def writes(i: I) = w(i)
  }

  implicit def zero[I]: Write[I, I] = Write(identity[I] _)

  import play.api.libs.functional._
  implicit def functionalCanBuildWrite[O](implicit m: Monoid[O]) = new FunctionalCanBuild[({type λ[I] = Write[I, O]})#λ] {
    def apply[A, B](wa: Write[A, O], wb: Write[B, O]): Write[A ~ B, O] = Write[A ~ B, O] { (x: A ~ B) =>
      x match {
        case a ~ b => m.append(wa.writes(a), wb.writes(b))
      }
    }
  }

  implicit def contravariantfunctorWrite[O] = new ContravariantFunctor[({type λ[I] = Write[I, O]})#λ] {
    def contramap[A, B](wa: Write[A, O], f: B => A): Write[B, O] = Write[B, O]( (b: B) => wa.writes(f(b)) )
  }

   // XXX: Helps the compiler a bit
  import play.api.libs.functional.syntax._
  implicit def fbo[I, O: Monoid](a: Write[I, O]) = toFunctionalBuilderOps[({type λ[I] = Write[I, O]})#λ, I](a)
  implicit def cfo[I, O](a: Write[I, O]) = toContraFunctorOps[({type λ[I] = Write[I, O]})#λ, I](a)

}