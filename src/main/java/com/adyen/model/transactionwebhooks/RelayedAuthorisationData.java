/*
 * Transaction webhooks
 *
 * The version of the OpenAPI document: 4
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.adyen.model.transactionwebhooks;

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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.core.JsonProcessingException;


/**
 * RelayedAuthorisationData
 */
@JsonPropertyOrder({
  RelayedAuthorisationData.JSON_PROPERTY_METADATA,
  RelayedAuthorisationData.JSON_PROPERTY_REFERENCE
})

public class RelayedAuthorisationData {
  public static final String JSON_PROPERTY_METADATA = "metadata";
  private Map<String, String> metadata = null;

  public static final String JSON_PROPERTY_REFERENCE = "reference";
  private String reference;

  public RelayedAuthorisationData() { 
  }

  /**
   * Contains key-value pairs of your references and descriptions, for example, &#x60;customId&#x60;:&#x60;your-own-custom-field-12345&#x60;.
   *
   * @param metadata
   * @return the current {@code RelayedAuthorisationData} instance, allowing for method chaining
   */
  public RelayedAuthorisationData metadata(Map<String, String> metadata) {
    this.metadata = metadata;
    return this;
  }

  public RelayedAuthorisationData putMetadataItem(String key, String metadataItem) {
    if (this.metadata == null) {
      this.metadata = new HashMap<>();
    }
    this.metadata.put(key, metadataItem);
    return this;
  }

  /**
   * Contains key-value pairs of your references and descriptions, for example, &#x60;customId&#x60;:&#x60;your-own-custom-field-12345&#x60;.
   * @return metadata
   */
  @ApiModelProperty(value = "Contains key-value pairs of your references and descriptions, for example, `customId`:`your-own-custom-field-12345`.")
  @JsonProperty(JSON_PROPERTY_METADATA)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public Map<String, String> getMetadata() {
    return metadata;
  }

  /**
   * Contains key-value pairs of your references and descriptions, for example, &#x60;customId&#x60;:&#x60;your-own-custom-field-12345&#x60;.
   *
   * @param metadata
   */ 
  @JsonProperty(JSON_PROPERTY_METADATA)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setMetadata(Map<String, String> metadata) {
    this.metadata = metadata;
  }

  /**
   * Your reference for the relayed authorisation data.
   *
   * @param reference
   * @return the current {@code RelayedAuthorisationData} instance, allowing for method chaining
   */
  public RelayedAuthorisationData reference(String reference) {
    this.reference = reference;
    return this;
  }

  /**
   * Your reference for the relayed authorisation data.
   * @return reference
   */
  @ApiModelProperty(value = "Your reference for the relayed authorisation data.")
  @JsonProperty(JSON_PROPERTY_REFERENCE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getReference() {
    return reference;
  }

  /**
   * Your reference for the relayed authorisation data.
   *
   * @param reference
   */ 
  @JsonProperty(JSON_PROPERTY_REFERENCE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setReference(String reference) {
    this.reference = reference;
  }

  /**
   * Return true if this RelayedAuthorisationData object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    RelayedAuthorisationData relayedAuthorisationData = (RelayedAuthorisationData) o;
    return Objects.equals(this.metadata, relayedAuthorisationData.metadata) &&
        Objects.equals(this.reference, relayedAuthorisationData.reference);
  }

  @Override
  public int hashCode() {
    return Objects.hash(metadata, reference);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class RelayedAuthorisationData {\n");
    sb.append("    metadata: ").append(toIndentedString(metadata)).append("\n");
    sb.append("    reference: ").append(toIndentedString(reference)).append("\n");
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
   * Create an instance of RelayedAuthorisationData given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of RelayedAuthorisationData
   * @throws JsonProcessingException if the JSON string is invalid with respect to RelayedAuthorisationData
   */
  public static RelayedAuthorisationData fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, RelayedAuthorisationData.class);
  }
/**
  * Convert an instance of RelayedAuthorisationData to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}
