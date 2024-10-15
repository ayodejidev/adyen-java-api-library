/*
 * Management API
 *
 * The version of the OpenAPI document: 3
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.adyen.model.management;

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
 * Address
 */
@JsonPropertyOrder({
  Address.JSON_PROPERTY_CITY,
  Address.JSON_PROPERTY_COMPANY_NAME,
  Address.JSON_PROPERTY_COUNTRY,
  Address.JSON_PROPERTY_POSTAL_CODE,
  Address.JSON_PROPERTY_STATE_OR_PROVINCE,
  Address.JSON_PROPERTY_STREET_ADDRESS,
  Address.JSON_PROPERTY_STREET_ADDRESS2
})

public class Address {
  public static final String JSON_PROPERTY_CITY = "city";
  private String city;

  public static final String JSON_PROPERTY_COMPANY_NAME = "companyName";
  private String companyName;

  public static final String JSON_PROPERTY_COUNTRY = "country";
  private String country;

  public static final String JSON_PROPERTY_POSTAL_CODE = "postalCode";
  private String postalCode;

  public static final String JSON_PROPERTY_STATE_OR_PROVINCE = "stateOrProvince";
  private String stateOrProvince;

  public static final String JSON_PROPERTY_STREET_ADDRESS = "streetAddress";
  private String streetAddress;

  public static final String JSON_PROPERTY_STREET_ADDRESS2 = "streetAddress2";
  private String streetAddress2;

  public Address() { 
  }

  /**
   * The name of the city.
   *
   * @param city
   * @return the current {@code Address} instance, allowing for method chaining
   */
  public Address city(String city) {
    this.city = city;
    return this;
  }

  /**
   * The name of the city.
   * @return city
   */
  @ApiModelProperty(value = "The name of the city.")
  @JsonProperty(JSON_PROPERTY_CITY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getCity() {
    return city;
  }

  /**
   * The name of the city.
   *
   * @param city
   */ 
  @JsonProperty(JSON_PROPERTY_CITY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setCity(String city) {
    this.city = city;
  }

  /**
   * The name of the company.
   *
   * @param companyName
   * @return the current {@code Address} instance, allowing for method chaining
   */
  public Address companyName(String companyName) {
    this.companyName = companyName;
    return this;
  }

  /**
   * The name of the company.
   * @return companyName
   */
  @ApiModelProperty(value = "The name of the company.")
  @JsonProperty(JSON_PROPERTY_COMPANY_NAME)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getCompanyName() {
    return companyName;
  }

  /**
   * The name of the company.
   *
   * @param companyName
   */ 
  @JsonProperty(JSON_PROPERTY_COMPANY_NAME)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setCompanyName(String companyName) {
    this.companyName = companyName;
  }

  /**
   * The two-letter country code, in [ISO 3166-1 alpha-2](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2) format.
   *
   * @param country
   * @return the current {@code Address} instance, allowing for method chaining
   */
  public Address country(String country) {
    this.country = country;
    return this;
  }

  /**
   * The two-letter country code, in [ISO 3166-1 alpha-2](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2) format.
   * @return country
   */
  @ApiModelProperty(value = "The two-letter country code, in [ISO 3166-1 alpha-2](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2) format.")
  @JsonProperty(JSON_PROPERTY_COUNTRY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getCountry() {
    return country;
  }

  /**
   * The two-letter country code, in [ISO 3166-1 alpha-2](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2) format.
   *
   * @param country
   */ 
  @JsonProperty(JSON_PROPERTY_COUNTRY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setCountry(String country) {
    this.country = country;
  }

  /**
   * The postal code.
   *
   * @param postalCode
   * @return the current {@code Address} instance, allowing for method chaining
   */
  public Address postalCode(String postalCode) {
    this.postalCode = postalCode;
    return this;
  }

  /**
   * The postal code.
   * @return postalCode
   */
  @ApiModelProperty(value = "The postal code.")
  @JsonProperty(JSON_PROPERTY_POSTAL_CODE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getPostalCode() {
    return postalCode;
  }

  /**
   * The postal code.
   *
   * @param postalCode
   */ 
  @JsonProperty(JSON_PROPERTY_POSTAL_CODE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setPostalCode(String postalCode) {
    this.postalCode = postalCode;
  }

  /**
   * The state or province as defined in [ISO 3166-2](https://www.iso.org/standard/72483.html). For example, **ON** for Ontario, Canada.   Applicable for the following countries: - Australia - Brazil - Canada - India - Mexico - New Zealand - United States
   *
   * @param stateOrProvince
   * @return the current {@code Address} instance, allowing for method chaining
   */
  public Address stateOrProvince(String stateOrProvince) {
    this.stateOrProvince = stateOrProvince;
    return this;
  }

  /**
   * The state or province as defined in [ISO 3166-2](https://www.iso.org/standard/72483.html). For example, **ON** for Ontario, Canada.   Applicable for the following countries: - Australia - Brazil - Canada - India - Mexico - New Zealand - United States
   * @return stateOrProvince
   */
  @ApiModelProperty(value = "The state or province as defined in [ISO 3166-2](https://www.iso.org/standard/72483.html). For example, **ON** for Ontario, Canada.   Applicable for the following countries: - Australia - Brazil - Canada - India - Mexico - New Zealand - United States")
  @JsonProperty(JSON_PROPERTY_STATE_OR_PROVINCE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getStateOrProvince() {
    return stateOrProvince;
  }

  /**
   * The state or province as defined in [ISO 3166-2](https://www.iso.org/standard/72483.html). For example, **ON** for Ontario, Canada.   Applicable for the following countries: - Australia - Brazil - Canada - India - Mexico - New Zealand - United States
   *
   * @param stateOrProvince
   */ 
  @JsonProperty(JSON_PROPERTY_STATE_OR_PROVINCE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setStateOrProvince(String stateOrProvince) {
    this.stateOrProvince = stateOrProvince;
  }

  /**
   * The name of the street, and the house or building number.
   *
   * @param streetAddress
   * @return the current {@code Address} instance, allowing for method chaining
   */
  public Address streetAddress(String streetAddress) {
    this.streetAddress = streetAddress;
    return this;
  }

  /**
   * The name of the street, and the house or building number.
   * @return streetAddress
   */
  @ApiModelProperty(value = "The name of the street, and the house or building number.")
  @JsonProperty(JSON_PROPERTY_STREET_ADDRESS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getStreetAddress() {
    return streetAddress;
  }

  /**
   * The name of the street, and the house or building number.
   *
   * @param streetAddress
   */ 
  @JsonProperty(JSON_PROPERTY_STREET_ADDRESS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setStreetAddress(String streetAddress) {
    this.streetAddress = streetAddress;
  }

  /**
   * Additional address details, if any.
   *
   * @param streetAddress2
   * @return the current {@code Address} instance, allowing for method chaining
   */
  public Address streetAddress2(String streetAddress2) {
    this.streetAddress2 = streetAddress2;
    return this;
  }

  /**
   * Additional address details, if any.
   * @return streetAddress2
   */
  @ApiModelProperty(value = "Additional address details, if any.")
  @JsonProperty(JSON_PROPERTY_STREET_ADDRESS2)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getStreetAddress2() {
    return streetAddress2;
  }

  /**
   * Additional address details, if any.
   *
   * @param streetAddress2
   */ 
  @JsonProperty(JSON_PROPERTY_STREET_ADDRESS2)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setStreetAddress2(String streetAddress2) {
    this.streetAddress2 = streetAddress2;
  }

  /**
   * Return true if this Address object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    Address address = (Address) o;
    return Objects.equals(this.city, address.city) &&
        Objects.equals(this.companyName, address.companyName) &&
        Objects.equals(this.country, address.country) &&
        Objects.equals(this.postalCode, address.postalCode) &&
        Objects.equals(this.stateOrProvince, address.stateOrProvince) &&
        Objects.equals(this.streetAddress, address.streetAddress) &&
        Objects.equals(this.streetAddress2, address.streetAddress2);
  }

  @Override
  public int hashCode() {
    return Objects.hash(city, companyName, country, postalCode, stateOrProvince, streetAddress, streetAddress2);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class Address {\n");
    sb.append("    city: ").append(toIndentedString(city)).append("\n");
    sb.append("    companyName: ").append(toIndentedString(companyName)).append("\n");
    sb.append("    country: ").append(toIndentedString(country)).append("\n");
    sb.append("    postalCode: ").append(toIndentedString(postalCode)).append("\n");
    sb.append("    stateOrProvince: ").append(toIndentedString(stateOrProvince)).append("\n");
    sb.append("    streetAddress: ").append(toIndentedString(streetAddress)).append("\n");
    sb.append("    streetAddress2: ").append(toIndentedString(streetAddress2)).append("\n");
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
   * Create an instance of Address given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of Address
   * @throws JsonProcessingException if the JSON string is invalid with respect to Address
   */
  public static Address fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, Address.class);
  }
/**
  * Convert an instance of Address to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}
