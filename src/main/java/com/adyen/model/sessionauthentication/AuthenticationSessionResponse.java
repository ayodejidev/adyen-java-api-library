/*
 * Session authentication API
 *
 * The version of the OpenAPI document: 1
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.adyen.model.sessionauthentication;

import java.util.Objects;
import java.util.Map;
import java.util.HashMap;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.annotation.JsonValue;
import java.util.Arrays;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.core.JsonProcessingException;


/**
 * AuthenticationSessionResponse
 */
@JsonPropertyOrder({
  AuthenticationSessionResponse.JSON_PROPERTY_ID,
  AuthenticationSessionResponse.JSON_PROPERTY_TOKEN
})

public class AuthenticationSessionResponse {
  public static final String JSON_PROPERTY_ID = "id";
  private String id;

  public static final String JSON_PROPERTY_TOKEN = "token";
  private String token;

  public AuthenticationSessionResponse() { 
  }

  /**
   * The unique identifier of the session.
   *
   * @param id
   * @return the current {@code AuthenticationSessionResponse} instance, allowing for method chaining
   */
  public AuthenticationSessionResponse id(String id) {
    this.id = id;
    return this;
  }

  /**
   * The unique identifier of the session.
   * @return id
   */
  @JsonProperty(JSON_PROPERTY_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getId() {
    return id;
  }

  /**
   * The unique identifier of the session.
   *
   * @param id
   */
  @JsonProperty(JSON_PROPERTY_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setId(String id) {
    this.id = id;
  }

  /**
   * The session token created.
   *
   * @param token
   * @return the current {@code AuthenticationSessionResponse} instance, allowing for method chaining
   */
  public AuthenticationSessionResponse token(String token) {
    this.token = token;
    return this;
  }

  /**
   * The session token created.
   * @return token
   */
  @JsonProperty(JSON_PROPERTY_TOKEN)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getToken() {
    return token;
  }

  /**
   * The session token created.
   *
   * @param token
   */
  @JsonProperty(JSON_PROPERTY_TOKEN)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setToken(String token) {
    this.token = token;
  }

  /**
   * Return true if this AuthenticationSessionResponse object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    AuthenticationSessionResponse authenticationSessionResponse = (AuthenticationSessionResponse) o;
    return Objects.equals(this.id, authenticationSessionResponse.id) &&
        Objects.equals(this.token, authenticationSessionResponse.token);
  }

  @Override
  public int hashCode() {
    return Objects.hash(id, token);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class AuthenticationSessionResponse {\n");
    sb.append("    id: ").append(toIndentedString(id)).append("\n");
    sb.append("    token: ").append(toIndentedString(token)).append("\n");
    sb.append("}");
    return sb.toString();
  }

  /**
   * Convert the given object to string with each line indented by 4 spaces
   * (except the first line).
   */
  private String toIndentedString(Object o) {
    if (o == null) {
      return "null";
    }
    return o.toString().replace("\n", "\n    ");
  }

/**
   * Create an instance of AuthenticationSessionResponse given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of AuthenticationSessionResponse
   * @throws JsonProcessingException if the JSON string is invalid with respect to AuthenticationSessionResponse
   */
  public static AuthenticationSessionResponse fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, AuthenticationSessionResponse.class);
  }
/**
  * Convert an instance of AuthenticationSessionResponse to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}
