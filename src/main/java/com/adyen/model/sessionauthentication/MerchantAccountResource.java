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
 * MerchantAccountResource
 */
@JsonPropertyOrder({
  MerchantAccountResource.JSON_PROPERTY_MERCHANT_ACCOUNT_CODE
})

@JsonIgnoreProperties(
  value = "type", // ignore manually set type, it will be automatically generated by Jackson during serialization
  allowSetters = true // allows the type to be set during deserialization
)
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.PROPERTY, property = "type", visible = true)

public class MerchantAccountResource extends Resource {
  public static final String JSON_PROPERTY_MERCHANT_ACCOUNT_CODE = "merchantAccountCode";
  private String merchantAccountCode;

  public MerchantAccountResource() { 
  }

  /**
   * merchantAccountCode
   *
   * @param merchantAccountCode
   * @return the current {@code MerchantAccountResource} instance, allowing for method chaining
   */
  public MerchantAccountResource merchantAccountCode(String merchantAccountCode) {
    this.merchantAccountCode = merchantAccountCode;
    return this;
  }

  /**
   * Get merchantAccountCode
   * @return merchantAccountCode
   */
  @JsonProperty(JSON_PROPERTY_MERCHANT_ACCOUNT_CODE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getMerchantAccountCode() {
    return merchantAccountCode;
  }

  /**
   * merchantAccountCode
   *
   * @param merchantAccountCode
   */
  @JsonProperty(JSON_PROPERTY_MERCHANT_ACCOUNT_CODE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setMerchantAccountCode(String merchantAccountCode) {
    this.merchantAccountCode = merchantAccountCode;
  }

  /**
   * Return true if this MerchantAccountResource object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    MerchantAccountResource merchantAccountResource = (MerchantAccountResource) o;
    return Objects.equals(this.merchantAccountCode, merchantAccountResource.merchantAccountCode) &&
        super.equals(o);
  }

  @Override
  public int hashCode() {
    return Objects.hash(merchantAccountCode, super.hashCode());
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class MerchantAccountResource {\n");
    sb.append("    ").append(toIndentedString(super.toString())).append("\n");
    sb.append("    merchantAccountCode: ").append(toIndentedString(merchantAccountCode)).append("\n");
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
    mappings.put("MerchantAccountResource", MerchantAccountResource.class);
    JSON.registerDiscriminator(MerchantAccountResource.class, "type", mappings);
  }
/**
   * Create an instance of MerchantAccountResource given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of MerchantAccountResource
   * @throws JsonProcessingException if the JSON string is invalid with respect to MerchantAccountResource
   */
  public static MerchantAccountResource fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, MerchantAccountResource.class);
  }
/**
  * Convert an instance of MerchantAccountResource to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}
