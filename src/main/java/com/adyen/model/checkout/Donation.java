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
import java.util.ArrayList;
import java.util.List;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.core.JsonProcessingException;


/**
 * Donation
 */
@JsonPropertyOrder({
  Donation.JSON_PROPERTY_CURRENCY,
  Donation.JSON_PROPERTY_DONATION_TYPE,
  Donation.JSON_PROPERTY_MAX_ROUNDUP_AMOUNT,
  Donation.JSON_PROPERTY_VALUES
})

public class Donation {
  public static final String JSON_PROPERTY_CURRENCY = "currency";
  private String currency;

  public static final String JSON_PROPERTY_DONATION_TYPE = "donationType";
  private String donationType;

  public static final String JSON_PROPERTY_MAX_ROUNDUP_AMOUNT = "maxRoundupAmount";
  private Long maxRoundupAmount;

  public static final String JSON_PROPERTY_VALUES = "values";
  private List<Long> values = null;

  public Donation() { 
  }

  public Donation currency(String currency) {
    this.currency = currency;
    return this;
  }

   /**
   * The three-character [ISO currency code](https://docs.adyen.com/development-resources/currency-codes/).
   * @return currency
  **/
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


  public Donation donationType(String donationType) {
    this.donationType = donationType;
    return this;
  }

   /**
   * The [type of donation](https://docs.adyen.com/online-payments/donations/#donation-types).  Possible values: * **roundup**: a donation where the original transaction amount is rounded up as a donation. * **fixedAmounts**: a donation where you show fixed donations amounts that the shopper can select from.
   * @return donationType
  **/
  @ApiModelProperty(required = true, value = "The [type of donation](https://docs.adyen.com/online-payments/donations/#donation-types).  Possible values: * **roundup**: a donation where the original transaction amount is rounded up as a donation. * **fixedAmounts**: a donation where you show fixed donations amounts that the shopper can select from.")
  @JsonProperty(JSON_PROPERTY_DONATION_TYPE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getDonationType() {
    return donationType;
  }


 /**
  * The [type of donation](https://docs.adyen.com/online-payments/donations/#donation-types).  Possible values: * **roundup**: a donation where the original transaction amount is rounded up as a donation. * **fixedAmounts**: a donation where you show fixed donations amounts that the shopper can select from.
  *
  * @param donationType
  */ 
  @JsonProperty(JSON_PROPERTY_DONATION_TYPE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setDonationType(String donationType) {
    this.donationType = donationType;
  }


  public Donation maxRoundupAmount(Long maxRoundupAmount) {
    this.maxRoundupAmount = maxRoundupAmount;
    return this;
  }

   /**
   * The maximum amount a transaction can be rounded up to make a donation. This field is only present when &#x60;donationType&#x60; is **roundup**.
   * @return maxRoundupAmount
  **/
  @ApiModelProperty(value = "The maximum amount a transaction can be rounded up to make a donation. This field is only present when `donationType` is **roundup**.")
  @JsonProperty(JSON_PROPERTY_MAX_ROUNDUP_AMOUNT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Long getMaxRoundupAmount() {
    return maxRoundupAmount;
  }


 /**
  * The maximum amount a transaction can be rounded up to make a donation. This field is only present when &#x60;donationType&#x60; is **roundup**.
  *
  * @param maxRoundupAmount
  */ 
  @JsonProperty(JSON_PROPERTY_MAX_ROUNDUP_AMOUNT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setMaxRoundupAmount(Long maxRoundupAmount) {
    this.maxRoundupAmount = maxRoundupAmount;
  }


  public Donation values(List<Long> values) {
    this.values = values;
    return this;
  }

  public Donation addValuesItem(Long valuesItem) {
    if (this.values == null) {
      this.values = new ArrayList<>();
    }
    this.values.add(valuesItem);
    return this;
  }

   /**
   * The fixed donation amounts in [minor units](https://docs.adyen.com/development-resources/currency-codes//#minor-units). This field is only present when &#x60;donationType&#x60; is **fixedAmounts**.
   * @return values
  **/
  @ApiModelProperty(value = "The fixed donation amounts in [minor units](https://docs.adyen.com/development-resources/currency-codes//#minor-units). This field is only present when `donationType` is **fixedAmounts**.")
  @JsonProperty(JSON_PROPERTY_VALUES)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public List<Long> getValues() {
    return values;
  }


 /**
  * The fixed donation amounts in [minor units](https://docs.adyen.com/development-resources/currency-codes//#minor-units). This field is only present when &#x60;donationType&#x60; is **fixedAmounts**.
  *
  * @param values
  */ 
  @JsonProperty(JSON_PROPERTY_VALUES)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setValues(List<Long> values) {
    this.values = values;
  }


  /**
   * Return true if this Donation object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    Donation donation = (Donation) o;
    return Objects.equals(this.currency, donation.currency) &&
        Objects.equals(this.donationType, donation.donationType) &&
        Objects.equals(this.maxRoundupAmount, donation.maxRoundupAmount) &&
        Objects.equals(this.values, donation.values);
  }

  @Override
  public int hashCode() {
    return Objects.hash(currency, donationType, maxRoundupAmount, values);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class Donation {\n");
    sb.append("    currency: ").append(toIndentedString(currency)).append("\n");
    sb.append("    donationType: ").append(toIndentedString(donationType)).append("\n");
    sb.append("    maxRoundupAmount: ").append(toIndentedString(maxRoundupAmount)).append("\n");
    sb.append("    values: ").append(toIndentedString(values)).append("\n");
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
   * Create an instance of Donation given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of Donation
   * @throws JsonProcessingException if the JSON string is invalid with respect to Donation
   */
  public static Donation fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, Donation.class);
  }
/**
  * Convert an instance of Donation to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}

