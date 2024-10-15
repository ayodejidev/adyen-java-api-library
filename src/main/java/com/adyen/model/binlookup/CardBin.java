/*
 * Adyen BinLookup API
 *
 * The version of the OpenAPI document: 54
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.adyen.model.binlookup;

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
 * CardBin
 */
@JsonPropertyOrder({
  CardBin.JSON_PROPERTY_BIN,
  CardBin.JSON_PROPERTY_COMMERCIAL,
  CardBin.JSON_PROPERTY_FUNDING_SOURCE,
  CardBin.JSON_PROPERTY_FUNDS_AVAILABILITY,
  CardBin.JSON_PROPERTY_ISSUER_BIN,
  CardBin.JSON_PROPERTY_ISSUING_BANK,
  CardBin.JSON_PROPERTY_ISSUING_COUNTRY,
  CardBin.JSON_PROPERTY_ISSUING_CURRENCY,
  CardBin.JSON_PROPERTY_PAYMENT_METHOD,
  CardBin.JSON_PROPERTY_PAYOUT_ELIGIBLE,
  CardBin.JSON_PROPERTY_SUMMARY
})

public class CardBin {
  public static final String JSON_PROPERTY_BIN = "bin";
  private String bin;

  public static final String JSON_PROPERTY_COMMERCIAL = "commercial";
  private Boolean commercial;

  public static final String JSON_PROPERTY_FUNDING_SOURCE = "fundingSource";
  private String fundingSource;

  public static final String JSON_PROPERTY_FUNDS_AVAILABILITY = "fundsAvailability";
  private String fundsAvailability;

  public static final String JSON_PROPERTY_ISSUER_BIN = "issuerBin";
  private String issuerBin;

  public static final String JSON_PROPERTY_ISSUING_BANK = "issuingBank";
  private String issuingBank;

  public static final String JSON_PROPERTY_ISSUING_COUNTRY = "issuingCountry";
  private String issuingCountry;

  public static final String JSON_PROPERTY_ISSUING_CURRENCY = "issuingCurrency";
  private String issuingCurrency;

  public static final String JSON_PROPERTY_PAYMENT_METHOD = "paymentMethod";
  private String paymentMethod;

  public static final String JSON_PROPERTY_PAYOUT_ELIGIBLE = "payoutEligible";
  private String payoutEligible;

  public static final String JSON_PROPERTY_SUMMARY = "summary";
  private String summary;

  public CardBin() { 
  }

  /**
   * The first 6 digit of the card number. Enable this field via merchant account settings.
   *
   * @param bin
   * @return the current {@code CardBin} instance, allowing for method chaining
   */
  public CardBin bin(String bin) {
    this.bin = bin;
    return this;
  }

  /**
   * The first 6 digit of the card number. Enable this field via merchant account settings.
   * @return bin
   */
  @ApiModelProperty(value = "The first 6 digit of the card number. Enable this field via merchant account settings.")
  @JsonProperty(JSON_PROPERTY_BIN)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getBin() {
    return bin;
  }

  /**
   * The first 6 digit of the card number. Enable this field via merchant account settings.
   *
   * @param bin
   */ 
  @JsonProperty(JSON_PROPERTY_BIN)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setBin(String bin) {
    this.bin = bin;
  }

  /**
   * If true, it indicates a commercial card. Enable this field via merchant account settings.
   *
   * @param commercial
   * @return the current {@code CardBin} instance, allowing for method chaining
   */
  public CardBin commercial(Boolean commercial) {
    this.commercial = commercial;
    return this;
  }

  /**
   * If true, it indicates a commercial card. Enable this field via merchant account settings.
   * @return commercial
   */
  @ApiModelProperty(value = "If true, it indicates a commercial card. Enable this field via merchant account settings.")
  @JsonProperty(JSON_PROPERTY_COMMERCIAL)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public Boolean getCommercial() {
    return commercial;
  }

  /**
   * If true, it indicates a commercial card. Enable this field via merchant account settings.
   *
   * @param commercial
   */ 
  @JsonProperty(JSON_PROPERTY_COMMERCIAL)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setCommercial(Boolean commercial) {
    this.commercial = commercial;
  }

  /**
   * The card funding source. Valid values are: * CHARGE * CREDIT * DEBIT * DEFERRED_DEBIT * PREPAID * PREPAID_RELOADABLE * PREPAID_NONRELOADABLE &gt; Enable this field via merchant account settings.
   *
   * @param fundingSource
   * @return the current {@code CardBin} instance, allowing for method chaining
   */
  public CardBin fundingSource(String fundingSource) {
    this.fundingSource = fundingSource;
    return this;
  }

  /**
   * The card funding source. Valid values are: * CHARGE * CREDIT * DEBIT * DEFERRED_DEBIT * PREPAID * PREPAID_RELOADABLE * PREPAID_NONRELOADABLE &gt; Enable this field via merchant account settings.
   * @return fundingSource
   */
  @ApiModelProperty(value = "The card funding source. Valid values are: * CHARGE * CREDIT * DEBIT * DEFERRED_DEBIT * PREPAID * PREPAID_RELOADABLE * PREPAID_NONRELOADABLE > Enable this field via merchant account settings.")
  @JsonProperty(JSON_PROPERTY_FUNDING_SOURCE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getFundingSource() {
    return fundingSource;
  }

  /**
   * The card funding source. Valid values are: * CHARGE * CREDIT * DEBIT * DEFERRED_DEBIT * PREPAID * PREPAID_RELOADABLE * PREPAID_NONRELOADABLE &gt; Enable this field via merchant account settings.
   *
   * @param fundingSource
   */ 
  @JsonProperty(JSON_PROPERTY_FUNDING_SOURCE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setFundingSource(String fundingSource) {
    this.fundingSource = fundingSource;
  }

  /**
   * Indicates availability of funds.  Visa: * \&quot;I\&quot; (fast funds are supported) * \&quot;N\&quot; (otherwise)  Mastercard: * \&quot;I\&quot; (product type is Prepaid or Debit, or issuing country is in CEE/HGEM list) * \&quot;N\&quot; (otherwise) &gt; Returned when you verify a card BIN or estimate costs, and only if &#x60;payoutEligible&#x60; is different from \&quot;N\&quot; or \&quot;U\&quot;.
   *
   * @param fundsAvailability
   * @return the current {@code CardBin} instance, allowing for method chaining
   */
  public CardBin fundsAvailability(String fundsAvailability) {
    this.fundsAvailability = fundsAvailability;
    return this;
  }

  /**
   * Indicates availability of funds.  Visa: * \&quot;I\&quot; (fast funds are supported) * \&quot;N\&quot; (otherwise)  Mastercard: * \&quot;I\&quot; (product type is Prepaid or Debit, or issuing country is in CEE/HGEM list) * \&quot;N\&quot; (otherwise) &gt; Returned when you verify a card BIN or estimate costs, and only if &#x60;payoutEligible&#x60; is different from \&quot;N\&quot; or \&quot;U\&quot;.
   * @return fundsAvailability
   */
  @ApiModelProperty(value = "Indicates availability of funds.  Visa: * \"I\" (fast funds are supported) * \"N\" (otherwise)  Mastercard: * \"I\" (product type is Prepaid or Debit, or issuing country is in CEE/HGEM list) * \"N\" (otherwise) > Returned when you verify a card BIN or estimate costs, and only if `payoutEligible` is different from \"N\" or \"U\".")
  @JsonProperty(JSON_PROPERTY_FUNDS_AVAILABILITY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getFundsAvailability() {
    return fundsAvailability;
  }

  /**
   * Indicates availability of funds.  Visa: * \&quot;I\&quot; (fast funds are supported) * \&quot;N\&quot; (otherwise)  Mastercard: * \&quot;I\&quot; (product type is Prepaid or Debit, or issuing country is in CEE/HGEM list) * \&quot;N\&quot; (otherwise) &gt; Returned when you verify a card BIN or estimate costs, and only if &#x60;payoutEligible&#x60; is different from \&quot;N\&quot; or \&quot;U\&quot;.
   *
   * @param fundsAvailability
   */ 
  @JsonProperty(JSON_PROPERTY_FUNDS_AVAILABILITY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setFundsAvailability(String fundsAvailability) {
    this.fundsAvailability = fundsAvailability;
  }

  /**
   * The first 8 digit of the card number. Enable this field via merchant account settings.
   *
   * @param issuerBin
   * @return the current {@code CardBin} instance, allowing for method chaining
   */
  public CardBin issuerBin(String issuerBin) {
    this.issuerBin = issuerBin;
    return this;
  }

  /**
   * The first 8 digit of the card number. Enable this field via merchant account settings.
   * @return issuerBin
   */
  @ApiModelProperty(value = "The first 8 digit of the card number. Enable this field via merchant account settings.")
  @JsonProperty(JSON_PROPERTY_ISSUER_BIN)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getIssuerBin() {
    return issuerBin;
  }

  /**
   * The first 8 digit of the card number. Enable this field via merchant account settings.
   *
   * @param issuerBin
   */ 
  @JsonProperty(JSON_PROPERTY_ISSUER_BIN)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setIssuerBin(String issuerBin) {
    this.issuerBin = issuerBin;
  }

  /**
   * The issuing bank of the card.
   *
   * @param issuingBank
   * @return the current {@code CardBin} instance, allowing for method chaining
   */
  public CardBin issuingBank(String issuingBank) {
    this.issuingBank = issuingBank;
    return this;
  }

  /**
   * The issuing bank of the card.
   * @return issuingBank
   */
  @ApiModelProperty(value = "The issuing bank of the card.")
  @JsonProperty(JSON_PROPERTY_ISSUING_BANK)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getIssuingBank() {
    return issuingBank;
  }

  /**
   * The issuing bank of the card.
   *
   * @param issuingBank
   */ 
  @JsonProperty(JSON_PROPERTY_ISSUING_BANK)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setIssuingBank(String issuingBank) {
    this.issuingBank = issuingBank;
  }

  /**
   * The country where the card was issued from.
   *
   * @param issuingCountry
   * @return the current {@code CardBin} instance, allowing for method chaining
   */
  public CardBin issuingCountry(String issuingCountry) {
    this.issuingCountry = issuingCountry;
    return this;
  }

  /**
   * The country where the card was issued from.
   * @return issuingCountry
   */
  @ApiModelProperty(value = "The country where the card was issued from.")
  @JsonProperty(JSON_PROPERTY_ISSUING_COUNTRY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getIssuingCountry() {
    return issuingCountry;
  }

  /**
   * The country where the card was issued from.
   *
   * @param issuingCountry
   */ 
  @JsonProperty(JSON_PROPERTY_ISSUING_COUNTRY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setIssuingCountry(String issuingCountry) {
    this.issuingCountry = issuingCountry;
  }

  /**
   * The currency of the card.
   *
   * @param issuingCurrency
   * @return the current {@code CardBin} instance, allowing for method chaining
   */
  public CardBin issuingCurrency(String issuingCurrency) {
    this.issuingCurrency = issuingCurrency;
    return this;
  }

  /**
   * The currency of the card.
   * @return issuingCurrency
   */
  @ApiModelProperty(value = "The currency of the card.")
  @JsonProperty(JSON_PROPERTY_ISSUING_CURRENCY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getIssuingCurrency() {
    return issuingCurrency;
  }

  /**
   * The currency of the card.
   *
   * @param issuingCurrency
   */ 
  @JsonProperty(JSON_PROPERTY_ISSUING_CURRENCY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setIssuingCurrency(String issuingCurrency) {
    this.issuingCurrency = issuingCurrency;
  }

  /**
   * The payment method associated with the card (e.g. visa, mc, or amex).
   *
   * @param paymentMethod
   * @return the current {@code CardBin} instance, allowing for method chaining
   */
  public CardBin paymentMethod(String paymentMethod) {
    this.paymentMethod = paymentMethod;
    return this;
  }

  /**
   * The payment method associated with the card (e.g. visa, mc, or amex).
   * @return paymentMethod
   */
  @ApiModelProperty(value = "The payment method associated with the card (e.g. visa, mc, or amex).")
  @JsonProperty(JSON_PROPERTY_PAYMENT_METHOD)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getPaymentMethod() {
    return paymentMethod;
  }

  /**
   * The payment method associated with the card (e.g. visa, mc, or amex).
   *
   * @param paymentMethod
   */ 
  @JsonProperty(JSON_PROPERTY_PAYMENT_METHOD)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setPaymentMethod(String paymentMethod) {
    this.paymentMethod = paymentMethod;
  }

  /**
   * Indicates whether a payout is eligible or not for this card.  Visa: * \&quot;Y\&quot; * \&quot;N\&quot;  Mastercard: * \&quot;Y\&quot; (domestic and cross-border) * \&quot;D\&quot; (only domestic) * \&quot;N\&quot; (no MoneySend) * \&quot;U\&quot; (unknown) &gt; Returned when you verify a card BIN or estimate costs, and only if &#x60;payoutEligible&#x60; is different from \&quot;N\&quot; or \&quot;U\&quot;.
   *
   * @param payoutEligible
   * @return the current {@code CardBin} instance, allowing for method chaining
   */
  public CardBin payoutEligible(String payoutEligible) {
    this.payoutEligible = payoutEligible;
    return this;
  }

  /**
   * Indicates whether a payout is eligible or not for this card.  Visa: * \&quot;Y\&quot; * \&quot;N\&quot;  Mastercard: * \&quot;Y\&quot; (domestic and cross-border) * \&quot;D\&quot; (only domestic) * \&quot;N\&quot; (no MoneySend) * \&quot;U\&quot; (unknown) &gt; Returned when you verify a card BIN or estimate costs, and only if &#x60;payoutEligible&#x60; is different from \&quot;N\&quot; or \&quot;U\&quot;.
   * @return payoutEligible
   */
  @ApiModelProperty(value = "Indicates whether a payout is eligible or not for this card.  Visa: * \"Y\" * \"N\"  Mastercard: * \"Y\" (domestic and cross-border) * \"D\" (only domestic) * \"N\" (no MoneySend) * \"U\" (unknown) > Returned when you verify a card BIN or estimate costs, and only if `payoutEligible` is different from \"N\" or \"U\".")
  @JsonProperty(JSON_PROPERTY_PAYOUT_ELIGIBLE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getPayoutEligible() {
    return payoutEligible;
  }

  /**
   * Indicates whether a payout is eligible or not for this card.  Visa: * \&quot;Y\&quot; * \&quot;N\&quot;  Mastercard: * \&quot;Y\&quot; (domestic and cross-border) * \&quot;D\&quot; (only domestic) * \&quot;N\&quot; (no MoneySend) * \&quot;U\&quot; (unknown) &gt; Returned when you verify a card BIN or estimate costs, and only if &#x60;payoutEligible&#x60; is different from \&quot;N\&quot; or \&quot;U\&quot;.
   *
   * @param payoutEligible
   */ 
  @JsonProperty(JSON_PROPERTY_PAYOUT_ELIGIBLE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setPayoutEligible(String payoutEligible) {
    this.payoutEligible = payoutEligible;
  }

  /**
   * The last four digits of the card number.
   *
   * @param summary
   * @return the current {@code CardBin} instance, allowing for method chaining
   */
  public CardBin summary(String summary) {
    this.summary = summary;
    return this;
  }

  /**
   * The last four digits of the card number.
   * @return summary
   */
  @ApiModelProperty(value = "The last four digits of the card number.")
  @JsonProperty(JSON_PROPERTY_SUMMARY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getSummary() {
    return summary;
  }

  /**
   * The last four digits of the card number.
   *
   * @param summary
   */ 
  @JsonProperty(JSON_PROPERTY_SUMMARY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setSummary(String summary) {
    this.summary = summary;
  }

  /**
   * Return true if this CardBin object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    CardBin cardBin = (CardBin) o;
    return Objects.equals(this.bin, cardBin.bin) &&
        Objects.equals(this.commercial, cardBin.commercial) &&
        Objects.equals(this.fundingSource, cardBin.fundingSource) &&
        Objects.equals(this.fundsAvailability, cardBin.fundsAvailability) &&
        Objects.equals(this.issuerBin, cardBin.issuerBin) &&
        Objects.equals(this.issuingBank, cardBin.issuingBank) &&
        Objects.equals(this.issuingCountry, cardBin.issuingCountry) &&
        Objects.equals(this.issuingCurrency, cardBin.issuingCurrency) &&
        Objects.equals(this.paymentMethod, cardBin.paymentMethod) &&
        Objects.equals(this.payoutEligible, cardBin.payoutEligible) &&
        Objects.equals(this.summary, cardBin.summary);
  }

  @Override
  public int hashCode() {
    return Objects.hash(bin, commercial, fundingSource, fundsAvailability, issuerBin, issuingBank, issuingCountry, issuingCurrency, paymentMethod, payoutEligible, summary);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class CardBin {\n");
    sb.append("    bin: ").append(toIndentedString(bin)).append("\n");
    sb.append("    commercial: ").append(toIndentedString(commercial)).append("\n");
    sb.append("    fundingSource: ").append(toIndentedString(fundingSource)).append("\n");
    sb.append("    fundsAvailability: ").append(toIndentedString(fundsAvailability)).append("\n");
    sb.append("    issuerBin: ").append(toIndentedString(issuerBin)).append("\n");
    sb.append("    issuingBank: ").append(toIndentedString(issuingBank)).append("\n");
    sb.append("    issuingCountry: ").append(toIndentedString(issuingCountry)).append("\n");
    sb.append("    issuingCurrency: ").append(toIndentedString(issuingCurrency)).append("\n");
    sb.append("    paymentMethod: ").append(toIndentedString(paymentMethod)).append("\n");
    sb.append("    payoutEligible: ").append(toIndentedString(payoutEligible)).append("\n");
    sb.append("    summary: ").append(toIndentedString(summary)).append("\n");
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
   * Create an instance of CardBin given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of CardBin
   * @throws JsonProcessingException if the JSON string is invalid with respect to CardBin
   */
  public static CardBin fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, CardBin.class);
  }
/**
  * Convert an instance of CardBin to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}
