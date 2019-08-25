package com.asaraff.plat.auth.core;

import java.util.HashMap;
import java.util.Map;


public class Claims {

  private String uuid;
  private Application application;


  public String getUuid() {
    return uuid;
  }

  public void setUuid(String uuid) {
    this.uuid = uuid;
  }

  public Application getApplication() {
    return application;
  }

  public void setApplication(Application application) {
    this.application = application;
  }

  public Map<String,Object> toClaimsSet() {
    Map<String,Object> claimsSet = new HashMap<>();
    if (uuid != null) {
      claimsSet.put(CustomClaimKeys.uuid.name(), uuid);
    }
    if (application != null) {
      claimsSet.put(CustomClaimKeys.application.name(), application.getName());
    }
    return claimsSet;
  }

  public static class Builder {

    private String uuid;
    private Application application;


    public Builder uuid(String uuid) {
      this.uuid = uuid;
      return this;
    }

    public Builder applicationName(String applicationName) {
      this.application = Application.fromName(applicationName);
      return this;
    }

    public Builder claimsSet(Map<String,Object> claimsSet) {
      Object claim;
      if ((claim = claimsSet.get(CustomClaimKeys.uuid.name())) != null) {
        uuid = claim.toString();
      }
      if ((claim = claimsSet.get(CustomClaimKeys.application.name())) != null) {
        application = Application.fromName(claim.toString());
      }
      return this;
    }

    public Claims build() {

      Claims claims = new Claims();
      claims.setUuid(uuid);
      claims.setApplication(application);

      return claims;
    }
  }
}
