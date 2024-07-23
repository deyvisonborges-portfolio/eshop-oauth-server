package com.deyvisonborges.eshop.authorizer.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Test {
  @Value("${rsa.public}")
  private String publicRSA;

  @GetMapping("/test")
  public String getVars() {
    return publicRSA;
  }
}
