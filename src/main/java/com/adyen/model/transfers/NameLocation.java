/*
 * Transfers API
 *
 * The version of the OpenAPI document: 4
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.adyen.model.transfers;

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
 * NameLocation
 */
@JsonPropertyOrder({
  NameLocation.JSON_PROPERTY_CITY,
  NameLocation.JSON_PROPERTY_COUNTRY,
  NameLocation.JSON_PROPERTY_COUNTRY_OF_ORIGIN,
  NameLocation.JSON_PROPERTY_NAME,
  NameLocation.JSON_PROPERTY_RAW_DATA,
  NameLocation.JSON_PROPERTY_STATE
})

public class NameLocation {
  public static final String JSON_PROPERTY_CITY = "city";
  private String city;

  public static final String JSON_PROPERTY_COUNTRY = "country";
  private String country;

  public static final String JSON_PROPERTY_COUNTRY_OF_ORIGIN = "countryOfOrigin";
  private String countryOfOrigin;

  public static final String JSON_PROPERTY_NAME = "name";
  private String name;

  public static final String JSON_PROPERTY_RAW_DATA = "rawData";
  private String rawData;

  public static final String JSON_PROPERTY_STATE = "state";
  private String state;

  public NameLocation() { 
  }

  /**
   * The city where the merchant is located.
   *
   * @param city
   * @return the current {@code NameLocation} instance, allowing for method chaining
   */
  public NameLocation city(String city) {
    this.city = city;
    return this;
  }

  /**
   * The city where the merchant is located.
   * @return city
   */
  @ApiModelProperty(value = "The city where the merchant is located.")
  @JsonProperty(JSON_PROPERTY_CITY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getCity() {
    return city;
  }

  /**
   * The city where the merchant is located.
   *
   * @param city
   */ 
  @JsonProperty(JSON_PROPERTY_CITY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setCity(String city) {
    this.city = city;
  }

  /**
   * The country where the merchant is located in [three-letter country code](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-3) format.
   *
   * @param country
   * @return the current {@code NameLocation} instance, allowing for method chaining
   */
  public NameLocation country(String country) {
    this.country = country;
    return this;
  }

  /**
   * The country where the merchant is located in [three-letter country code](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-3) format.
   * @return country
   */
  @ApiModelProperty(value = "The country where the merchant is located in [three-letter country code](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-3) format.")
  @JsonProperty(JSON_PROPERTY_COUNTRY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getCountry() {
    return country;
  }

  /**
   * The country where the merchant is located in [three-letter country code](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-3) format.
   *
   * @param country
   */ 
  @JsonProperty(JSON_PROPERTY_COUNTRY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setCountry(String country) {
    this.country = country;
  }

  /**
   * The home country in [three-digit country code](https://en.wikipedia.org/wiki/ISO_3166-1_numeric) format, used for government-controlled merchants such as embassies.
   *
   * @param countryOfOrigin
   * @return the current {@code NameLocation} instance, allowing for method chaining
   */
  public NameLocation countryOfOrigin(String countryOfOrigin) {
    this.countryOfOrigin = countryOfOrigin;
    return this;
  }

  /**
   * The home country in [three-digit country code](https://en.wikipedia.org/wiki/ISO_3166-1_numeric) format, used for government-controlled merchants such as embassies.
   * @return countryOfOrigin
   */
  @ApiModelProperty(value = "The home country in [three-digit country code](https://en.wikipedia.org/wiki/ISO_3166-1_numeric) format, used for government-controlled merchants such as embassies.")
  @JsonProperty(JSON_PROPERTY_COUNTRY_OF_ORIGIN)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getCountryOfOrigin() {
    return countryOfOrigin;
  }

  /**
   * The home country in [three-digit country code](https://en.wikipedia.org/wiki/ISO_3166-1_numeric) format, used for government-controlled merchants such as embassies.
   *
   * @param countryOfOrigin
   */ 
  @JsonProperty(JSON_PROPERTY_COUNTRY_OF_ORIGIN)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setCountryOfOrigin(String countryOfOrigin) {
    this.countryOfOrigin = countryOfOrigin;
  }

  /**
   * The name of the merchant&#39;s shop or service.
   *
   * @param name
   * @return the current {@code NameLocation} instance, allowing for method chaining
   */
  public NameLocation name(String name) {
    this.name = name;
    return this;
  }

  /**
   * The name of the merchant&#39;s shop or service.
   * @return name
   */
  @ApiModelProperty(value = "The name of the merchant's shop or service.")
  @JsonProperty(JSON_PROPERTY_NAME)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getName() {
    return name;
  }

  /**
   * The name of the merchant&#39;s shop or service.
   *
   * @param name
   */ 
  @JsonProperty(JSON_PROPERTY_NAME)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setName(String name) {
    this.name = name;
  }

  /**
   * The raw data.
   *
   * @param rawData
   * @return the current {@code NameLocation} instance, allowing for method chaining
   */
  public NameLocation rawData(String rawData) {
    this.rawData = rawData;
    return this;
  }

  /**
   * The raw data.
   * @return rawData
   */
  @ApiModelProperty(value = "The raw data.")
  @JsonProperty(JSON_PROPERTY_RAW_DATA)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getRawData() {
    return rawData;
  }

  /**
   * The raw data.
   *
   * @param rawData
   */ 
  @JsonProperty(JSON_PROPERTY_RAW_DATA)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setRawData(String rawData) {
    this.rawData = rawData;
  }

  /**
   * The state where the merchant is located.
   *
   * @param state
   * @return the current {@code NameLocation} instance, allowing for method chaining
   */
  public NameLocation state(String state) {
    this.state = state;
    return this;
  }

  /**
   * The state where the merchant is located.
   * @return state
   */
  @ApiModelProperty(value = "The state where the merchant is located.")
  @JsonProperty(JSON_PROPERTY_STATE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getState() {
    return state;
  }

  /**
   * The state where the merchant is located.
   *
   * @param state
   */ 
  @JsonProperty(JSON_PROPERTY_STATE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setState(String state) {
    this.state = state;
  }

  /**
   * Return true if this NameLocation object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    NameLocation nameLocation = (NameLocation) o;
    return Objects.equals(this.city, nameLocation.city) &&
        Objects.equals(this.country, nameLocation.country) &&
        Objects.equals(this.countryOfOrigin, nameLocation.countryOfOrigin) &&
        Objects.equals(this.name, nameLocation.name) &&
        Objects.equals(this.rawData, nameLocation.rawData) &&
        Objects.equals(this.state, nameLocation.state);
  }

  @Override
  public int hashCode() {
    return Objects.hash(city, country, countryOfOrigin, name, rawData, state);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class NameLocation {\n");
    sb.append("    city: ").append(toIndentedString(city)).append("\n");
    sb.append("    country: ").append(toIndentedString(country)).append("\n");
    sb.append("    countryOfOrigin: ").append(toIndentedString(countryOfOrigin)).append("\n");
    sb.append("    name: ").append(toIndentedString(name)).append("\n");
    sb.append("    rawData: ").append(toIndentedString(rawData)).append("\n");
    sb.append("    state: ").append(toIndentedString(state)).append("\n");
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
   * Create an instance of NameLocation given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of NameLocation
   * @throws JsonProcessingException if the JSON string is invalid with respect to NameLocation
   */
  public static NameLocation fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, NameLocation.class);
  }
/**
  * Convert an instance of NameLocation to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}
