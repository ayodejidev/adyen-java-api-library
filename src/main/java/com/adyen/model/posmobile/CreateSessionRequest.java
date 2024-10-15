/*
 * POS Mobile API
 *
 * The version of the OpenAPI document: 68
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.adyen.model.posmobile;

import java.util.Objects;
import java.util.Arrays;
import java.util.Map;
import java.util.HashMap;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.annotation.JsonValue;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.core.JsonProcessingException;


/**
 * CreateSessionRequest
 */
@JsonPropertyOrder({
  CreateSessionRequest.JSON_PROPERTY_MERCHANT_ACCOUNT,
  CreateSessionRequest.JSON_PROPERTY_SETUP_TOKEN,
  CreateSessionRequest.JSON_PROPERTY_STORE
})

public class CreateSessionRequest {
  public static final String JSON_PROPERTY_MERCHANT_ACCOUNT = "merchantAccount";
  private String merchantAccount;

  public static final String JSON_PROPERTY_SETUP_TOKEN = "setupToken";
  private String setupToken;

  public static final String JSON_PROPERTY_STORE = "store";
  private String store;

  public CreateSessionRequest() { 
  }

  /**
   * The unique identifier of your merchant account.
   *
   * @param merchantAccount
   * @return the current {@code CreateSessionRequest} instance, allowing for method chaining
   */
  public CreateSessionRequest merchantAccount(String merchantAccount) {
    this.merchantAccount = merchantAccount;
    return this;
  }

  /**
   * The unique identifier of your merchant account.
   * @return merchantAccount
   */
  @ApiModelProperty(required = true, value = "The unique identifier of your merchant account.")
  @JsonProperty(JSON_PROPERTY_MERCHANT_ACCOUNT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getMerchantAccount() {
    return merchantAccount;
  }

  /**
   * The unique identifier of your merchant account.
   *
   * @param merchantAccount
   */ 
  @JsonProperty(JSON_PROPERTY_MERCHANT_ACCOUNT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setMerchantAccount(String merchantAccount) {
    this.merchantAccount = merchantAccount;
  }

  /**
   * The setup token provided by the POS Mobile SDK.  - When using the Android POS Mobile SDK, obtain the token through the &#x60;AuthenticationService.authenticate(setupToken)&#x60; callback of &#x60;AuthenticationService&#x60;.  - When using the iOS POS Mobile SDK, obtain the token through the &#x60;PaymentServiceDelegate.register(with:)&#x60; callback of &#x60;PaymentServiceDelegate&#x60;.
   *
   * @param setupToken
   * @return the current {@code CreateSessionRequest} instance, allowing for method chaining
   */
  public CreateSessionRequest setupToken(String setupToken) {
    this.setupToken = setupToken;
    return this;
  }

  /**
   * The setup token provided by the POS Mobile SDK.  - When using the Android POS Mobile SDK, obtain the token through the &#x60;AuthenticationService.authenticate(setupToken)&#x60; callback of &#x60;AuthenticationService&#x60;.  - When using the iOS POS Mobile SDK, obtain the token through the &#x60;PaymentServiceDelegate.register(with:)&#x60; callback of &#x60;PaymentServiceDelegate&#x60;.
   * @return setupToken
   */
  @ApiModelProperty(required = true, value = "The setup token provided by the POS Mobile SDK.  - When using the Android POS Mobile SDK, obtain the token through the `AuthenticationService.authenticate(setupToken)` callback of `AuthenticationService`.  - When using the iOS POS Mobile SDK, obtain the token through the `PaymentServiceDelegate.register(with:)` callback of `PaymentServiceDelegate`.")
  @JsonProperty(JSON_PROPERTY_SETUP_TOKEN)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getSetupToken() {
    return setupToken;
  }

  /**
   * The setup token provided by the POS Mobile SDK.  - When using the Android POS Mobile SDK, obtain the token through the &#x60;AuthenticationService.authenticate(setupToken)&#x60; callback of &#x60;AuthenticationService&#x60;.  - When using the iOS POS Mobile SDK, obtain the token through the &#x60;PaymentServiceDelegate.register(with:)&#x60; callback of &#x60;PaymentServiceDelegate&#x60;.
   *
   * @param setupToken
   */ 
  @JsonProperty(JSON_PROPERTY_SETUP_TOKEN)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setSetupToken(String setupToken) {
    this.setupToken = setupToken;
  }

  /**
   * The unique identifier of the store that you want to process transactions for.
   *
   * @param store
   * @return the current {@code CreateSessionRequest} instance, allowing for method chaining
   */
  public CreateSessionRequest store(String store) {
    this.store = store;
    return this;
  }

  /**
   * The unique identifier of the store that you want to process transactions for.
   * @return store
   */
  @ApiModelProperty(value = "The unique identifier of the store that you want to process transactions for.")
  @JsonProperty(JSON_PROPERTY_STORE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getStore() {
    return store;
  }

  /**
   * The unique identifier of the store that you want to process transactions for.
   *
   * @param store
   */ 
  @JsonProperty(JSON_PROPERTY_STORE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setStore(String store) {
    this.store = store;
  }

  /**
   * Return true if this CreateSessionRequest object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    CreateSessionRequest createSessionRequest = (CreateSessionRequest) o;
    return Objects.equals(this.merchantAccount, createSessionRequest.merchantAccount) &&
        Objects.equals(this.setupToken, createSessionRequest.setupToken) &&
        Objects.equals(this.store, createSessionRequest.store);
  }

  @Override
  public int hashCode() {
    return Objects.hash(merchantAccount, setupToken, store);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class CreateSessionRequest {\n");
    sb.append("    merchantAccount: ").append(toIndentedString(merchantAccount)).append("\n");
    sb.append("    setupToken: ").append(toIndentedString(setupToken)).append("\n");
    sb.append("    store: ").append(toIndentedString(store)).append("\n");
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
   * Create an instance of CreateSessionRequest given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of CreateSessionRequest
   * @throws JsonProcessingException if the JSON string is invalid with respect to CreateSessionRequest
   */
  public static CreateSessionRequest fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, CreateSessionRequest.class);
  }
/**
  * Convert an instance of CreateSessionRequest to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}
