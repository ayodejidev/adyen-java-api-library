/*
 * Configuration webhooks
 *
 * The version of the OpenAPI document: 1
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.adyen.model.configurationwebhooks;

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
 * Expiry
 */
@JsonPropertyOrder({
  Expiry.JSON_PROPERTY_MONTH,
  Expiry.JSON_PROPERTY_YEAR
})

public class Expiry {
  public static final String JSON_PROPERTY_MONTH = "month";
  private String month;

  public static final String JSON_PROPERTY_YEAR = "year";
  private String year;

  public Expiry() { 
  }

  public Expiry month(String month) {
    this.month = month;
    return this;
  }

   /**
   * The month in which the card will expire.
   * @return month
  **/
  @ApiModelProperty(value = "The month in which the card will expire.")
  @JsonProperty(JSON_PROPERTY_MONTH)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getMonth() {
    return month;
  }


 /**
  * The month in which the card will expire.
  *
  * @param month
  */ 
  @JsonProperty(JSON_PROPERTY_MONTH)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setMonth(String month) {
    this.month = month;
  }


  public Expiry year(String year) {
    this.year = year;
    return this;
  }

   /**
   * The year in which the card will expire.
   * @return year
  **/
  @ApiModelProperty(value = "The year in which the card will expire.")
  @JsonProperty(JSON_PROPERTY_YEAR)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getYear() {
    return year;
  }


 /**
  * The year in which the card will expire.
  *
  * @param year
  */ 
  @JsonProperty(JSON_PROPERTY_YEAR)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setYear(String year) {
    this.year = year;
  }


  /**
   * Return true if this Expiry object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    Expiry expiry = (Expiry) o;
    return Objects.equals(this.month, expiry.month) &&
        Objects.equals(this.year, expiry.year);
  }

  @Override
  public int hashCode() {
    return Objects.hash(month, year);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class Expiry {\n");
    sb.append("    month: ").append(toIndentedString(month)).append("\n");
    sb.append("    year: ").append(toIndentedString(year)).append("\n");
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
   * Create an instance of Expiry given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of Expiry
   * @throws JsonProcessingException if the JSON string is invalid with respect to Expiry
   */
  public static Expiry fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, Expiry.class);
  }
/**
  * Convert an instance of Expiry to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}

