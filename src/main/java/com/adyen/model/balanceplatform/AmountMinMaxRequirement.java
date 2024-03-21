/*
 * Configuration API
 *
 * The version of the OpenAPI document: 2
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.adyen.model.balanceplatform;

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
 * AmountMinMaxRequirement
 */
@JsonPropertyOrder({
  AmountMinMaxRequirement.JSON_PROPERTY_DESCRIPTION,
  AmountMinMaxRequirement.JSON_PROPERTY_MAX,
  AmountMinMaxRequirement.JSON_PROPERTY_MIN,
  AmountMinMaxRequirement.JSON_PROPERTY_TYPE
})

public class AmountMinMaxRequirement {
  public static final String JSON_PROPERTY_DESCRIPTION = "description";
  private String description;

  public static final String JSON_PROPERTY_MAX = "max";
  private Long max;

  public static final String JSON_PROPERTY_MIN = "min";
  private Long min;

  /**
   * **amountMinMaxRequirement**
   */
  public enum TypeEnum {
    AMOUNTMINMAXREQUIREMENT("amountMinMaxRequirement");

    private String value;

    TypeEnum(String value) {
      this.value = value;
    }

    @JsonValue
    public String getValue() {
      return value;
    }

    @Override
    public String toString() {
      return String.valueOf(value);
    }

    @JsonCreator
    public static TypeEnum fromValue(String value) {
      for (TypeEnum b : TypeEnum.values()) {
        if (b.value.equals(value)) {
          return b;
        }
      }
      throw new IllegalArgumentException("Unexpected value '" + value + "'");
    }
  }

  public static final String JSON_PROPERTY_TYPE = "type";
  private TypeEnum type;

  public AmountMinMaxRequirement() { 
  }

  public AmountMinMaxRequirement description(String description) {
    this.description = description;
    return this;
  }

   /**
   * Specifies the eligible amounts for a particular route.
   * @return description
  **/
  @ApiModelProperty(value = "Specifies the eligible amounts for a particular route.")
  @JsonProperty(JSON_PROPERTY_DESCRIPTION)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getDescription() {
    return description;
  }


 /**
  * Specifies the eligible amounts for a particular route.
  *
  * @param description
  */ 
  @JsonProperty(JSON_PROPERTY_DESCRIPTION)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setDescription(String description) {
    this.description = description;
  }


  public AmountMinMaxRequirement max(Long max) {
    this.max = max;
    return this;
  }

   /**
   * Maximum amount.
   * @return max
  **/
  @ApiModelProperty(value = "Maximum amount.")
  @JsonProperty(JSON_PROPERTY_MAX)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Long getMax() {
    return max;
  }


 /**
  * Maximum amount.
  *
  * @param max
  */ 
  @JsonProperty(JSON_PROPERTY_MAX)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setMax(Long max) {
    this.max = max;
  }


  public AmountMinMaxRequirement min(Long min) {
    this.min = min;
    return this;
  }

   /**
   * Minimum amount.
   * @return min
  **/
  @ApiModelProperty(value = "Minimum amount.")
  @JsonProperty(JSON_PROPERTY_MIN)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Long getMin() {
    return min;
  }


 /**
  * Minimum amount.
  *
  * @param min
  */ 
  @JsonProperty(JSON_PROPERTY_MIN)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setMin(Long min) {
    this.min = min;
  }


  public AmountMinMaxRequirement type(TypeEnum type) {
    this.type = type;
    return this;
  }

   /**
   * **amountMinMaxRequirement**
   * @return type
  **/
  @ApiModelProperty(required = true, value = "**amountMinMaxRequirement**")
  @JsonProperty(JSON_PROPERTY_TYPE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public TypeEnum getType() {
    return type;
  }


 /**
  * **amountMinMaxRequirement**
  *
  * @param type
  */ 
  @JsonProperty(JSON_PROPERTY_TYPE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setType(TypeEnum type) {
    this.type = type;
  }


  /**
   * Return true if this AmountMinMaxRequirement object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    AmountMinMaxRequirement amountMinMaxRequirement = (AmountMinMaxRequirement) o;
    return Objects.equals(this.description, amountMinMaxRequirement.description) &&
        Objects.equals(this.max, amountMinMaxRequirement.max) &&
        Objects.equals(this.min, amountMinMaxRequirement.min) &&
        Objects.equals(this.type, amountMinMaxRequirement.type);
  }

  @Override
  public int hashCode() {
    return Objects.hash(description, max, min, type);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class AmountMinMaxRequirement {\n");
    sb.append("    description: ").append(toIndentedString(description)).append("\n");
    sb.append("    max: ").append(toIndentedString(max)).append("\n");
    sb.append("    min: ").append(toIndentedString(min)).append("\n");
    sb.append("    type: ").append(toIndentedString(type)).append("\n");
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
   * Create an instance of AmountMinMaxRequirement given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of AmountMinMaxRequirement
   * @throws JsonProcessingException if the JSON string is invalid with respect to AmountMinMaxRequirement
   */
  public static AmountMinMaxRequirement fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, AmountMinMaxRequirement.class);
  }
/**
  * Convert an instance of AmountMinMaxRequirement to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}

