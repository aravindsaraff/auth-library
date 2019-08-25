package com.asaraff.plat.auth.core;

public enum Application {
  USER_ADMIN("User Admin"),
  UMS("Underwriting Management System"),
  PITSTOP("Pitstop"),
  DYNAMIC_LENDING("Dynamic Lending"),
  BORROWER_PORTAL("Borrower Portal"),
  OPS_PORTAL("Ops Portal"),
  CLIENT_PORTAL("Client Portal"),
  FASTTRACK("FastTrack");

  private String name;

  public static Application fromName(String name) {

    Application application = null;

    for (Application value: Application.values()) {
      if (value.getName().equals(name)) {
        application = value;
        break;
      }
    }

    return application;
  }

  private Application(String name) {
    this.name = name;
  }

  public String getName() {
    return name;
  }

  public boolean isOps() {
    return getName().startsWith("Ops");
  }

  public boolean isClient() {
    return getName().startsWith("Client");
  }
  public boolean isFastTrack() {
    return getName().startsWith("Fast");
  }
}