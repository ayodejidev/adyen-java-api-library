/*
 * Adyen Checkout API
 *
 * The version of the OpenAPI document: 71
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.adyen.model.checkout;

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
 * DonationCampaignsRequest
 */
@JsonPropertyOrder({
  DonationCampaignsRequest.JSON_PROPERTY_CURRENCY,
  DonationCampaignsRequest.JSON_PROPERTY_LOCALE,
  DonationCampaignsRequest.JSON_PROPERTY_MERCHANT_ACCOUNT
})

public class DonationCampaignsRequest {
  public static final String JSON_PROPERTY_CURRENCY = "currency";
  private String currency;

  public static final String JSON_PROPERTY_LOCALE = "locale";
  private String locale;

  public static final String JSON_PROPERTY_MERCHANT_ACCOUNT = "merchantAccount";
  private String merchantAccount;

  public DonationCampaignsRequest() { 
  }

  /**
   * The three-character [ISO currency code](https://docs.adyen.com/development-resources/currency-codes/).
   *
   * @param currency
   * @return the current {@code DonationCampaignsRequest} instance, allowing for method chaining
   */
  public DonationCampaignsRequest currency(String currency) {
    this.currency = currency;
    return this;
  }

  /**
   * The three-character [ISO currency code](https://docs.adyen.com/development-resources/currency-codes/).
   * @return currency
   */
  @ApiModelProperty(required = true, value = "The three-character [ISO currency code](https://docs.adyen.com/development-resources/currency-codes/).")
  @JsonProperty(JSON_PROPERTY_CURRENCY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getCurrency() {
    return currency;
  }

  /**
   * The three-character [ISO currency code](https://docs.adyen.com/development-resources/currency-codes/).
   *
   * @param currency
   */ 
  @JsonProperty(JSON_PROPERTY_CURRENCY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setCurrency(String currency) {
    this.currency = currency;
  }

  /**
   * Locale on the shopper interaction device.
   *
   * @param locale
   * @return the current {@code DonationCampaignsRequest} instance, allowing for method chaining
   */
  public DonationCampaignsRequest locale(String locale) {
    this.locale = locale;
    return this;
  }

  /**
   * Locale on the shopper interaction device.
   * @return locale
   */
  @ApiModelProperty(value = "Locale on the shopper interaction device.")
  @JsonProperty(JSON_PROPERTY_LOCALE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getLocale() {
    return locale;
  }

  /**
   * Locale on the shopper interaction device.
   *
   * @param locale
   */ 
  @JsonProperty(JSON_PROPERTY_LOCALE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setLocale(String locale) {
    this.locale = locale;
  }

  /**
   * Your merchant account identifier.
   *
   * @param merchantAccount
   * @return the current {@code DonationCampaignsRequest} instance, allowing for method chaining
   */
  public DonationCampaignsRequest merchantAccount(String merchantAccount) {
    this.merchantAccount = merchantAccount;
    return this;
  }

  /**
   * Your merchant account identifier.
   * @return merchantAccount
   */
  @ApiModelProperty(required = true, value = "Your merchant account identifier.")
  @JsonProperty(JSON_PROPERTY_MERCHANT_ACCOUNT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getMerchantAccount() {
    return merchantAccount;
  }

  /**
   * Your merchant account identifier.
   *
   * @param merchantAccount
   */ 
  @JsonProperty(JSON_PROPERTY_MERCHANT_ACCOUNT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setMerchantAccount(String merchantAccount) {
    this.merchantAccount = merchantAccount;
  }

  /**
   * Return true if this DonationCampaignsRequest object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    DonationCampaignsRequest donationCampaignsRequest = (DonationCampaignsRequest) o;
    return Objects.equals(this.currency, donationCampaignsRequest.currency) &&
        Objects.equals(this.locale, donationCampaignsRequest.locale) &&
        Objects.equals(this.merchantAccount, donationCampaignsRequest.merchantAccount);
  }

  @Override
  public int hashCode() {
    return Objects.hash(currency, locale, merchantAccount);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class DonationCampaignsRequest {\n");
    sb.append("    currency: ").append(toIndentedString(currency)).append("\n");
    sb.append("    locale: ").append(toIndentedString(locale)).append("\n");
    sb.append("    merchantAccount: ").append(toIndentedString(merchantAccount)).append("\n");
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
   * Create an instance of DonationCampaignsRequest given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of DonationCampaignsRequest
   * @throws JsonProcessingException if the JSON string is invalid with respect to DonationCampaignsRequest
   */
  public static DonationCampaignsRequest fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, DonationCampaignsRequest.class);
  }
/**
  * Convert an instance of DonationCampaignsRequest to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}
