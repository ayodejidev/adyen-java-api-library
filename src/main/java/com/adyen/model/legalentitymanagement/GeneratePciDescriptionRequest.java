/*
 * Legal Entity Management API
 *
 * The version of the OpenAPI document: 3
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.adyen.model.legalentitymanagement;

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
 * GeneratePciDescriptionRequest
 */
@JsonPropertyOrder({
  GeneratePciDescriptionRequest.JSON_PROPERTY_ADDITIONAL_SALES_CHANNELS,
  GeneratePciDescriptionRequest.JSON_PROPERTY_LANGUAGE
})

public class GeneratePciDescriptionRequest {
  /**
   * Gets or Sets additionalSalesChannels
   */
  public enum AdditionalSalesChannelsEnum {
    ECOMMERCE("eCommerce"),
    
    ECOMMOTO("ecomMoto"),
    
    POS("pos"),
    
    POSMOTO("posMoto");

    private String value;

    AdditionalSalesChannelsEnum(String value) {
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
    public static AdditionalSalesChannelsEnum fromValue(String value) {
      for (AdditionalSalesChannelsEnum b : AdditionalSalesChannelsEnum.values()) {
        if (b.value.equals(value)) {
          return b;
        }
      }
      throw new IllegalArgumentException("Unexpected value '" + value + "'");
    }
  }

  public static final String JSON_PROPERTY_ADDITIONAL_SALES_CHANNELS = "additionalSalesChannels";
  private List<AdditionalSalesChannelsEnum> additionalSalesChannels = null;

  public static final String JSON_PROPERTY_LANGUAGE = "language";
  private String language;

  public GeneratePciDescriptionRequest() { 
  }

  public GeneratePciDescriptionRequest additionalSalesChannels(List<AdditionalSalesChannelsEnum> additionalSalesChannels) {
    this.additionalSalesChannels = additionalSalesChannels;
    return this;
  }

  public GeneratePciDescriptionRequest addAdditionalSalesChannelsItem(AdditionalSalesChannelsEnum additionalSalesChannelsItem) {
    if (this.additionalSalesChannels == null) {
      this.additionalSalesChannels = new ArrayList<>();
    }
    this.additionalSalesChannels.add(additionalSalesChannelsItem);
    return this;
  }

   /**
   * An array of additional sales channels to generate PCI questionnaires. Include the relevant sales channels if you need your user to sign PCI questionnaires. Not required if you [create stores](https://docs.adyen.com/platforms) and [add payment methods](https://docs.adyen.com/adyen-for-platforms-model) before you generate the questionnaires.  Possible values: *  **eCommerce** *  **pos** *  **ecomMoto** *  **posMoto**  
   * @return additionalSalesChannels
  **/
  @ApiModelProperty(value = "An array of additional sales channels to generate PCI questionnaires. Include the relevant sales channels if you need your user to sign PCI questionnaires. Not required if you [create stores](https://docs.adyen.com/platforms) and [add payment methods](https://docs.adyen.com/adyen-for-platforms-model) before you generate the questionnaires.  Possible values: *  **eCommerce** *  **pos** *  **ecomMoto** *  **posMoto**  ")
  @JsonProperty(JSON_PROPERTY_ADDITIONAL_SALES_CHANNELS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public List<AdditionalSalesChannelsEnum> getAdditionalSalesChannels() {
    return additionalSalesChannels;
  }


 /**
  * An array of additional sales channels to generate PCI questionnaires. Include the relevant sales channels if you need your user to sign PCI questionnaires. Not required if you [create stores](https://docs.adyen.com/platforms) and [add payment methods](https://docs.adyen.com/adyen-for-platforms-model) before you generate the questionnaires.  Possible values: *  **eCommerce** *  **pos** *  **ecomMoto** *  **posMoto**  
  *
  * @param additionalSalesChannels
  */ 
  @JsonProperty(JSON_PROPERTY_ADDITIONAL_SALES_CHANNELS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setAdditionalSalesChannels(List<AdditionalSalesChannelsEnum> additionalSalesChannels) {
    this.additionalSalesChannels = additionalSalesChannels;
  }


  public GeneratePciDescriptionRequest language(String language) {
    this.language = language;
    return this;
  }

   /**
   * Sets the language of the PCI questionnaire. Its value is a two-character [ISO 639-1](https://en.wikipedia.org/wiki/ISO_639-1) language code, for example, **en**.
   * @return language
  **/
  @ApiModelProperty(value = "Sets the language of the PCI questionnaire. Its value is a two-character [ISO 639-1](https://en.wikipedia.org/wiki/ISO_639-1) language code, for example, **en**.")
  @JsonProperty(JSON_PROPERTY_LANGUAGE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getLanguage() {
    return language;
  }


 /**
  * Sets the language of the PCI questionnaire. Its value is a two-character [ISO 639-1](https://en.wikipedia.org/wiki/ISO_639-1) language code, for example, **en**.
  *
  * @param language
  */ 
  @JsonProperty(JSON_PROPERTY_LANGUAGE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setLanguage(String language) {
    this.language = language;
  }


  /**
   * Return true if this GeneratePciDescriptionRequest object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    GeneratePciDescriptionRequest generatePciDescriptionRequest = (GeneratePciDescriptionRequest) o;
    return Objects.equals(this.additionalSalesChannels, generatePciDescriptionRequest.additionalSalesChannels) &&
        Objects.equals(this.language, generatePciDescriptionRequest.language);
  }

  @Override
  public int hashCode() {
    return Objects.hash(additionalSalesChannels, language);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class GeneratePciDescriptionRequest {\n");
    sb.append("    additionalSalesChannels: ").append(toIndentedString(additionalSalesChannels)).append("\n");
    sb.append("    language: ").append(toIndentedString(language)).append("\n");
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
   * Create an instance of GeneratePciDescriptionRequest given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of GeneratePciDescriptionRequest
   * @throws JsonProcessingException if the JSON string is invalid with respect to GeneratePciDescriptionRequest
   */
  public static GeneratePciDescriptionRequest fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, GeneratePciDescriptionRequest.class);
  }
/**
  * Convert an instance of GeneratePciDescriptionRequest to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}

