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
 * UninstallAndroidCertificateDetails
 */
@JsonPropertyOrder({
  UninstallAndroidCertificateDetails.JSON_PROPERTY_CERTIFICATE_ID,
  UninstallAndroidCertificateDetails.JSON_PROPERTY_TYPE
})

public class UninstallAndroidCertificateDetails {
  public static final String JSON_PROPERTY_CERTIFICATE_ID = "certificateId";
  private String certificateId;

  /**
   * Type of terminal action: Uninstall an Android certificate.
   */
  public enum TypeEnum {
    UNINSTALLANDROIDCERTIFICATE("UninstallAndroidCertificate");

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

  public UninstallAndroidCertificateDetails() { 
  }

  /**
   * The unique identifier of the certificate to be uninstalled.
   *
   * @param certificateId
   * @return the current {@code UninstallAndroidCertificateDetails} instance, allowing for method chaining
   */
  public UninstallAndroidCertificateDetails certificateId(String certificateId) {
    this.certificateId = certificateId;
    return this;
  }

  /**
   * The unique identifier of the certificate to be uninstalled.
   * @return certificateId
   */
  @ApiModelProperty(value = "The unique identifier of the certificate to be uninstalled.")
  @JsonProperty(JSON_PROPERTY_CERTIFICATE_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getCertificateId() {
    return certificateId;
  }

  /**
   * The unique identifier of the certificate to be uninstalled.
   *
   * @param certificateId
   */ 
  @JsonProperty(JSON_PROPERTY_CERTIFICATE_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setCertificateId(String certificateId) {
    this.certificateId = certificateId;
  }

  /**
   * Type of terminal action: Uninstall an Android certificate.
   *
   * @param type
   * @return the current {@code UninstallAndroidCertificateDetails} instance, allowing for method chaining
   */
  public UninstallAndroidCertificateDetails type(TypeEnum type) {
    this.type = type;
    return this;
  }

  /**
   * Type of terminal action: Uninstall an Android certificate.
   * @return type
   */
  @ApiModelProperty(value = "Type of terminal action: Uninstall an Android certificate.")
  @JsonProperty(JSON_PROPERTY_TYPE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public TypeEnum getType() {
    return type;
  }

  /**
   * Type of terminal action: Uninstall an Android certificate.
   *
   * @param type
   */ 
  @JsonProperty(JSON_PROPERTY_TYPE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setType(TypeEnum type) {
    this.type = type;
  }

  /**
   * Return true if this UninstallAndroidCertificateDetails object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    UninstallAndroidCertificateDetails uninstallAndroidCertificateDetails = (UninstallAndroidCertificateDetails) o;
    return Objects.equals(this.certificateId, uninstallAndroidCertificateDetails.certificateId) &&
        Objects.equals(this.type, uninstallAndroidCertificateDetails.type);
  }

  @Override
  public int hashCode() {
    return Objects.hash(certificateId, type);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class UninstallAndroidCertificateDetails {\n");
    sb.append("    certificateId: ").append(toIndentedString(certificateId)).append("\n");
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
   * Create an instance of UninstallAndroidCertificateDetails given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of UninstallAndroidCertificateDetails
   * @throws JsonProcessingException if the JSON string is invalid with respect to UninstallAndroidCertificateDetails
   */
  public static UninstallAndroidCertificateDetails fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, UninstallAndroidCertificateDetails.class);
  }
/**
  * Convert an instance of UninstallAndroidCertificateDetails to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}
