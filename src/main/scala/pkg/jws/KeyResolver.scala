package pkg.jws

import cats.data.EitherT
import cats.implicits._
import pkg.jwk.Jwk

import scala.concurrent.{ExecutionContext, Future}

trait KeyResolver {
  def resolve[A](header: JwsHeader, payload: A): EitherT[Future, String, Jwk]
}
object KeyResolver {
  implicit def fromSingleKey(key: Jwk)(implicit ex: ExecutionContext): KeyResolver = new KeyResolver {
    def resolve[A](header: JwsHeader, payload: A) = EitherT.rightT[Future, String](key)
  }
}