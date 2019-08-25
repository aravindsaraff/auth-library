package com.asaraff.plat.auth.core;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.Map;

public class AccessTokenGeneratorTest {
    // this is a test
  private String sharedSecret = "N3204I2ET042naJ0hh4Il4Il34uBEYHr2dC48V0k44Q72362t3";
  private AccessTokenGenerator accessTokenGenerator;
  private String opsRole = "User";

  @Before
  public void setUp() throws Exception {
    accessTokenGenerator = new AccessTokenGenerator(sharedSecret);
  }

  @Test
  public void testExtractSubjectId() throws Exception {
    String subjectId = "testUser";
    String token = accessTokenGenerator.generateAccessToken(subjectId, "opsPortal", opsRole);
    String targetSubjectId = accessTokenGenerator.extractSubjectId(token);
    Assert.assertEquals("subjectIds are same", targetSubjectId, subjectId);
  }

  @Test
  public void testExtractClaimsSet() throws Exception {
    String subjectId = "testUser";
    String applicationName = "opsPortal";
    String token = accessTokenGenerator.generateAccessToken(subjectId, applicationName, opsRole);
    Map<String, Object> claimsMap = accessTokenGenerator.extractClaimsSet(token);
    Assert.assertTrue(claimsMap.containsKey("application"));
    Assert.assertEquals("Claims Map has valid application", applicationName, claimsMap.get("application"));
  }
}