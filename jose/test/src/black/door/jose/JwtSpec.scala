package black.door.jose

import java.time.Instant
import java.util.{Base64, Date}
import black.door.jose.jwk.{P256KeyPair, RsaPrivateKey}
import black.door.jose.jws.JwsHeader
import black.door.jose.jwt.{Check, Claims, Jwt, JwtValidator}
import black.door.jose.test.{left, right}
import com.nimbusds.jose.crypto.{ECDSASigner, ECDSAVerifier, RSASSAVerifier}
import com.nimbusds.jose.jwk.{ECKey, RSAKey}
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jose.{JWSAlgorithm, JWSHeader}
import com.nimbusds.jwt.{JWTClaimsSet, SignedJWT}
import org.scalatest._
import flatspec._
import matchers._

import scala.concurrent.ExecutionContext.Implicits.global

trait JwtSpec extends AnyFlatSpec with should.Matchers {

  implicit def headerSerializer: ByteSerializer[JwsHeader]
  implicit def headerDeserializer: ByteDeserializer[JwsHeader]
  implicit def payloadUnitSerializer: ByteSerializer[Claims[Unit]]
  implicit def payloadCustomSerializer: ByteSerializer[Claims[MyCustomClaimsClass]]
  implicit def payloadUnitDeserializer: ByteDeserializer[Claims[Unit]]
  implicit def payloadCustomDeserializer: ByteDeserializer[Claims[MyCustomClaimsClass]]

  val es256Key: P256KeyPair = P256KeyPair.generate.withAlg(Some("ES256"))
  val rsaKey: RSAKey        = new RSAKeyGenerator(2048).generate

  def generateToken = {
    val claims = Claims(jti = Some("test token id"))
    Jwt.sign(claims, es256Key)
  }

  "JWT signing" should "trim base64url padding" in {
    val compact                                  = generateToken
    val Array(headerC, payloadC, signatureC, _*) = compact.split('.')
    headerC should not contain '='
    payloadC should not contain '='
    signatureC should not contain '='
  }

  it should "sign with ES256" in {
    val claims  = Claims(jti = Some("test token id"), exp = Some(Instant.now.plusSeconds(600)))
    val compact = Jwt.sign(claims, es256Key)

    val encoder = Base64.getUrlEncoder
    val nimbusJwk = ECKey.parse(s"""{"kty":"EC","crv":"P-256","x":"${encoder.encodeToString(
      es256Key.x.toByteArray
    )}","y":"${encoder.encodeToString(es256Key.y.toByteArray)}"}""")
    val nimbusVerifier = new ECDSAVerifier(nimbusJwk)
    SignedJWT.parse(compact).verify(nimbusVerifier) shouldBe true
  }

  it should "sign with RS256" in {
    val privateJwk = RsaPrivateKey(
      n = rsaKey.getModulus.decodeToBigInteger(),
      e = rsaKey.getPublicExponent.decodeToBigInteger(),
      d = rsaKey.getPrivateExponent.decodeToBigInteger(),
      alg = Some("RS256")
    )
    val claims  = Claims(jti = Some("test token id"), exp = Some(Instant.now.plusSeconds(600)))
    val compact = Jwt.sign(claims, privateJwk)

    val nimbusPublicJwk = rsaKey.toPublicJWK
    val nimbusVerifier  = new RSASSAVerifier(nimbusPublicJwk)
    SignedJWT.parse(compact).verify(nimbusVerifier) shouldBe true
  }

  "JWT verification" should "parse and verify with ES256" in {
    val encoder = Base64.getUrlEncoder

    val nimbusJwk = ECKey.parse(
      s"""{"kty":"EC","crv":"P-256","d":"${encoder.encodeToString(
        es256Key.d.toByteArray
      )}","x":"${encoder.encodeToString(es256Key.x.toByteArray)}","y":"${encoder
        .encodeToString(
          es256Key.y.toByteArray
        )}"}"""
    )

    val claimsSet = new JWTClaimsSet.Builder()
      .jwtID("test token id")
      .expirationTime(Date.from(Instant.now.plusSeconds(600)))
      .build

    val signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).build, claimsSet)
    val signer    = new ECDSASigner(nimbusJwk)
    signedJWT.sign(signer)
    val compact = signedJWT.serialize

    Jwt.validate(compact).using(es256Key.toPublic).now shouldBe right
  }

  it should "fail for tokens before the nbf value" in {
    val claims  = Claims(nbf = Some(Instant.now.plusSeconds(60)))
    val compact = Jwt.sign(claims, es256Key)
    Jwt.validate(compact).using(es256Key).now shouldBe left
  }

  it should "fail for tokens after the exp value" in {
    val claims  = Claims(exp = Some(Instant.now.minusSeconds(60)))
    val compact = Jwt.sign(claims, es256Key)

    Jwt.validate(compact).using(es256Key).now shouldBe left
  }

  it should "fail for the wrong signature" in {
    val key2    = P256KeyPair.generate
    val compact = generateToken
    Jwt.validate("")[Unit]
    Jwt.validate(compact).using(key2).now shouldBe left
  }

  import Check._

  def validations[C] =
    JwtValidator.combine[C](
      Seq(
        aud(_ == "aud"),
        iss(_ == "iss"),
        sub(_ == "sub")
      )
    )

  it should "fail for the wrong iss value" in {
    val claims = Claims(
      iss = Some("miss"),
      aud = Some("aud"),
      sub = Some("sub")
    )
    val compact = Jwt.sign(claims, es256Key)
    Jwt.validate(compact).using(es256Key, jwtValidator = validations).now shouldBe left
  }

  it should "fail for the wrong aud value" in {
    val claims = Claims(
      iss = Some("iss"),
      aud = Some("miss"),
      sub = Some("sub")
    )
    val compact = Jwt.sign(claims, es256Key)
    Jwt.validate(compact).using(es256Key, jwtValidator = validations).now shouldBe left
  }

  it should "fail for the wrong sub value" in {
    val claims = Claims(
      iss = Some("iss"),
      aud = Some("aud"),
      sub = Some("miss")
    )
    val compact = Jwt.sign(claims, es256Key)
    Jwt.validate(compact).using(es256Key, jwtValidator = validations).now shouldBe left
  }

  it should "fail for missing iss value" in {
    val claims = Claims(
      aud = Some("aud"),
      sub = Some("sub")
    )
    val compact = Jwt.sign(claims, es256Key)
    Jwt.validate(compact).using(es256Key, jwtValidator = validations).now shouldBe left
  }

  it should "fail for missing aud value" in {
    val claims = Claims(
      iss = Some("iss"),
      sub = Some("sub")
    )
    val compact = Jwt.sign(claims, es256Key)
    Jwt.validate(compact).using(es256Key, jwtValidator = validations).now shouldBe left
  }

  it should "fail for missing sub value" in {
    val claims = Claims(
      iss = Some("iss"),
      aud = Some("aud")
    )
    val compact = Jwt.sign(claims, es256Key)
    Jwt.validate(compact).using(es256Key, jwtValidator = validations).now shouldBe left
  }

  it should "pass for correct claim values" in {
    val claims = Claims(
      iss = Some("iss"),
      aud = Some("aud"),
      sub = Some("sub")
    )
    val compact = Jwt.sign(claims, es256Key)
    Jwt.validate(compact).using(es256Key, jwtValidator = validations).now shouldBe right
  }

  it should "work with custom claims" in {
    val customValidator =
      Check
        .sub(_ == "you")
        .orElse(JwtValidator.fromSync[MyCustomClaimsClass] {
          case jwt if !jwt.claims.unregistered.thisTokenIsForAnAdmin =>
            "Token needs to be for an admin"
        })
        .orElse(Check.iss(_ == "me"))

    val claims =
      Claims(iss = Some("me"), sub = Some("you"), unregistered = MyCustomClaimsClass(false))
    val compact = Jwt.sign(claims, es256Key)

    Jwt
      .validate(compact)[MyCustomClaimsClass]
      .using(es256Key, customValidator)
      .now shouldBe left

    val claims2 =
      Claims(iss = Some("me"), sub = Some("you"), unregistered = MyCustomClaimsClass(true))
    val compact2 = Jwt.sign(claims2, es256Key)

    Jwt
      .validate(compact2)[MyCustomClaimsClass]
      .using(es256Key, customValidator)
      .now shouldBe right
  }
}

case class MyCustomClaimsClass(thisTokenIsForAnAdmin: Boolean)
