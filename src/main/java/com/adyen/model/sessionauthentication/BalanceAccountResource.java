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
import com.adyen.model.sessionauthentication.Resource;
import com.adyen.model.sessionauthentication.ResourceType;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.annotation.JsonValue;
import java.util.Arrays;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.core.JsonProcessingException;


/**
 * BalanceAccountResource
 */
@JsonPropertyOrder({
  BalanceAccountResource.JSON_PROPERTY_BALANCE_ACCOUNT_ID
})

@JsonIgnoreProperties(
  value = "type", // ignore manually set type, it will be automatically generated by Jackson during serialization
  allowSetters = true // allows the type to be set during deserialization
)
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.PROPERTY, property = "type", visible = true)

public class BalanceAccountResource extends Resource {
  public static final String JSON_PROPERTY_BALANCE_ACCOUNT_ID = "balanceAccountId";
  private String balanceAccountId;

  public BalanceAccountResource() { 
  }

  /**
   * balanceAccountId
   *
   * @param balanceAccountId
   * @return the current {@code BalanceAccountResource} instance, allowing for method chaining
   */
  public BalanceAccountResource balanceAccountId(String balanceAccountId) {
    this.balanceAccountId = balanceAccountId;
    return this;
  }

  /**
   * Get balanceAccountId
   * @return balanceAccountId
   */
  @JsonProperty(JSON_PROPERTY_BALANCE_ACCOUNT_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getBalanceAccountId() {
    return balanceAccountId;
  }

  /**
   * balanceAccountId
   *
   * @param balanceAccountId
   */
  @JsonProperty(JSON_PROPERTY_BALANCE_ACCOUNT_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setBalanceAccountId(String balanceAccountId) {
    this.balanceAccountId = balanceAccountId;
  }

  /**
   * Return true if this BalanceAccountResource object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    BalanceAccountResource balanceAccountResource = (BalanceAccountResource) o;
    return Objects.equals(this.balanceAccountId, balanceAccountResource.balanceAccountId) &&
        super.equals(o);
  }

  @Override
  public int hashCode() {
    return Objects.hash(balanceAccountId, super.hashCode());
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class BalanceAccountResource {\n");
    sb.append("    ").append(toIndentedString(super.toString())).append("\n");
    sb.append("    balanceAccountId: ").append(toIndentedString(balanceAccountId)).append("\n");
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

  static {
    // Initialize and register the discriminator mappings.
    Map<String, Class<?>> mappings = new HashMap<>();
    mappings.put("BalanceAccountResource", BalanceAccountResource.class);
    JSON.registerDiscriminator(BalanceAccountResource.class, "type", mappings);
  }
/**
   * Create an instance of BalanceAccountResource given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of BalanceAccountResource
   * @throws JsonProcessingException if the JSON string is invalid with respect to BalanceAccountResource
   */
  public static BalanceAccountResource fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, BalanceAccountResource.class);
  }
/**
  * Convert an instance of BalanceAccountResource to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}
