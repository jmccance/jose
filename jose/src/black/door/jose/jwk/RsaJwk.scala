package black.door.jose.jwk

import java.security.KeyFactory
import java.security.spec.{RSAPrivateKeySpec, RSAPublicKeySpec}
import scala.collection.immutable.Seq

sealed trait RsaJwk extends Jwk

case class RsaPublicKey(
    n: BigInt,
    e: BigInt,
    alg: Option[String] = None,
    use: Option[String] = None,
    key_ops: Option[Seq[String]] = None,
    kid: Option[String] = None
  ) extends RsaJwk
    with PublicJwk {
  val kty = "RSA"

  final def modulus  = n
  final def exponent = e

  lazy val toJcaPublicKey = {
    val spec    = new RSAPublicKeySpec(modulus.bigInteger, exponent.bigInteger)
    val factory = KeyFactory.getInstance("RSA")

    factory.generatePublic(spec)
  }

  def withAlg(alg: Option[String]) = copy(alg = alg)
}

case class RsaPrivateKey(
    n: BigInt,
    e: BigInt,
    d: BigInt,
    alg: Option[String] = None,
    use: Option[String] = None,
    key_ops: Option[Seq[String]] = None,
    kid: Option[String] = None
  ) extends RsaJwk
    with PrivateJwk {
  val kty = "RSA"

  private def modulus         = n
  private def privateExponent = d

  lazy val toJcaPrivateKey = {
    val spec    = new RSAPrivateKeySpec(modulus.bigInteger, privateExponent.bigInteger)
    val factory = KeyFactory.getInstance("RSA")

    factory.generatePrivate(spec)
  }

  def withAlg(alg: Option[String]) = copy(alg = alg)
}
