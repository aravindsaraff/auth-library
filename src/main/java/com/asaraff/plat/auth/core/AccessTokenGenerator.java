package com.asaraff.plat.auth.core;

import com.google.common.collect.Maps;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import lombok.extern.slf4j.Slf4j;

import org.apache.commons.lang3.StringUtils;
import org.joda.time.DateTime;

import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static com.nimbusds.jwt.SignedJWT.parse;


/**
 * This class encapsulates the token Generator. Token Generator is used in
 * Bearer token.
 */
@Slf4j
public final class AccessTokenGenerator {
  private static final String CLAIMS_ISSUER = "http://auth.asaraff.com";
  private static final JWSAlgorithm JWS_ALGORITHM = JWSAlgorithm.HS256;
  private static final String CUSTOM_CLAIMS = "CustomClaims";

  private String sharedSecret;


  public AccessTokenGenerator(String sharedSecret) {
    if (StringUtils.isAllBlank(sharedSecret)) {
      throw new IllegalArgumentException("Invalid shared secret");
    }
    this.sharedSecret = sharedSecret;
  }

  /**
   * Generates a access token to be used in every request.
   * Use the userId and current date in generating the access token
   *
   * @param subjectId    The (subject)id to be used in the JWT token creation. For example, for auth-token we use a User-Id.
   * @param @deprecated application Application Name - This is deprecated
   * @param appRole Name of Application+Role
   * @return Serialized version of above data
   * @see <a href="http://connect2id.com/assets/products/nimbus-jose-jwt/javadoc/index.html">Nimbus-JOSE-JWT</a>
   * @see <a href="http://connect2id.com/products/nimbus-jose-jwt/examples/jwt-with-hmac">JWT with HMAC</a>
   */
  public String generateAccessToken(String subjectId, String application, String appRole) {
    log.info("Generating access Token for Input {}", subjectId);

    // Need a claims set for JWT
    JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
      .issuer(CLAIMS_ISSUER)
      .subject(subjectId)
      .issueTime(new DateTime().toDate())
      .claim(CustomClaimKeys.uuid.name(), UUID.randomUUID().toString())
      .claim(CustomClaimKeys.application.name(), application)
      .claim(CustomClaimKeys.applicationRole.name(), appRole)
      .build();

    // Apply HMAC- Hashing Message Authentication Code
    try {

      JWSSigner jwsSigner = new MACSigner(sharedSecret);
      // Need to find out why 512 is not allowed
      //jwsSigner.supportedJWSAlgorithms();
      // Sign the request with internal algorithm
      SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWS_ALGORITHM), jwtClaimsSet);
      signedJWT.sign(jwsSigner);

      return signedJWT.serialize();
    } catch (JOSEException e) {
      log.error("Could not Generate Access token for id {}", subjectId, e);
      return ""; // this is an error condition if the token is empty(blank/null)
    }
  }

  /**
   * Generates a access token to be used in every request.
   * Use the userId and current date in generating the access token
   * FIXME - Merge with the above code
   *
   * @param subjectId    The (subject)id to be used in the JWT token creation. For example, for auth-token we use a User-Id.
   * @param appRoles Name of Application+Role List
   * @return Serialized version of above data
   * @see <a href="http://connect2id.com/assets/products/nimbus-jose-jwt/javadoc/index.html">Nimbus-JOSE-JWT</a>
   * @see <a href="http://connect2id.com/products/nimbus-jose-jwt/examples/jwt-with-hmac">JWT with HMAC</a>
   */
  public String generateAccessToken(String subjectId, String application, List<String> appRoles) {
    log.info("(Overloaded method)Generating access Token for Input {}", subjectId);

    // Need a claims set for JWT
    JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
      .issuer(CLAIMS_ISSUER)
      .subject(subjectId)
      .issueTime(new DateTime().toDate())
      .claim(CustomClaimKeys.uuid.name(), UUID.randomUUID().toString())
      .claim(CustomClaimKeys.application.name(), application)
      .build();

    JWTClaimsSet.Builder additionaClaimsBuilder = new JWTClaimsSet.Builder(jwtClaimsSet);

    // we get unmodifiable collection-map from JWT. So have to jump some hoops
    if(appRoles.size() > 1) {
      // with multiple roles, we need a qualifier for each role which is currently a number
      int applicationRoleCounter = 1;
      for(String appRoleName : appRoles) {//effectively final in Lambda tripping to use in streams.forEach
        additionaClaimsBuilder.claim(CustomClaimKeys.applicationRole.name() + applicationRoleCounter++, appRoleName);
      }
    } else {
      additionaClaimsBuilder.claim(CustomClaimKeys.applicationRole.name(), appRoles.get(0));
    }

    // Apply HMAC- Hashing Message Authentication Code
    try {
      JWSSigner jwsSigner = new MACSigner(sharedSecret);

      /*JWSSigner options = new JWTSigner.Options();
      options.setAlgorithm(Algorithm.HS512);*/

      // Sign the request with internal algorithm
      SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWS_ALGORITHM), additionaClaimsBuilder.build());

      signedJWT.sign(jwsSigner);
      return signedJWT.serialize();
    } catch (JOSEException e) {
      log.error("Could not Generate Access token for id {}", subjectId, e);
      return ""; // this is an error condition if the token is empty(blank/null)
    }
  }

  /**
   * Validates the existence of token. This API ONLY validates a "proper" token by applying the verifier.
   *
   * @param token        The JWT token to be deserialized.
   * @return True if token is validated. False otherwise
   */
  public boolean isValidAccessToken(String token) {
    try {
      // if any of the input is blank, no contest.
      if (StringUtils.isBlank(token)) {
        return false;
      }
      // Test the token for sign validity
      SignedJWT signedJWT = parse(token);
      JWSVerifier jwsVerifier = new MACVerifier(sharedSecret);
      return signedJWT.verify(jwsVerifier);

    } catch (JOSEException | ParseException e) {
      log.error("Exception deserialize the token {}", token, e);
      return false;
    }
  }

  /**
   * Cracks open the token and returns the subject ID used when creating it.
   * @param token        The JWT token to be deserialized.
   * @return The subject ID (For Platform, it is  UserId)
   */
  public String extractSubjectId(String token) {
    String subjectId = null;
    try {
      if (isValidAccessToken(token)) {
        SignedJWT signedJWT = parse(token);
        subjectId = signedJWT.getJWTClaimsSet().getSubject();
      }
    } catch (ParseException e) {
      log.error("Exception getting Subject Id the token {}", token, e);
    }
    return subjectId;
  }

  /**
   * Cracks open the token and returns the subject ID + custom ClaimsSet used when creating it.
   * @param token        The JWT access token to be deserialized.
   * @return Map of subjectId and custom claims-Set entries
   */
  public Map<String, Object> extractClaimsSet(String token) {
    Map<String, Object> customClaims = Maps.newHashMap();
    try {

      if (isValidAccessToken(token)) {
        SignedJWT signedJWT = parse(token);
        String subjectId = signedJWT.getJWTClaimsSet().getSubject();

        // we get unmodifiable collection-map from JWT. We convert to modifiable and add our own arbitrary mapset
        customClaims.putAll(signedJWT.getJWTClaimsSet().getClaims());
        customClaims.put(CustomClaimKeys.subjectId.name(), subjectId);

      }
    } catch (ParseException e) {
      log.error("Exception getting Claims-Set from the token {}", token, e);
    }
    return customClaims;
  }

  public String generateToken(Map<String,Object> claims) {

    // need a claims set for JWT
    JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
      .issuer(CLAIMS_ISSUER)
      .issueTime(DateTime.now().toDate())
      .claim(CUSTOM_CLAIMS, claims)
      .build();


    // apply HMAC - Hashing Message Authentication Code
    try {

      // sign the request with internal algorithm
      JWSSigner jwsSigner = new MACSigner(sharedSecret);
      SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWS_ALGORITHM), jwtClaimsSet);

      signedJWT.sign(jwsSigner);
      return signedJWT.serialize();
    } catch (JOSEException e) {
      throw new RuntimeException(e);
    }

  }

  public Map<String,Object> getTokenClaims(String token) {
    try {

      return parse(token).getJWTClaimsSet().getClaims();

    } catch (ParseException e) {
      throw new RuntimeException(e);
    }
  }

}