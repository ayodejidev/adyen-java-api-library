/*
 * Legal Entity Management API
 *
 * The version of the OpenAPI document: 3
 * Contact: developer-experience@adyen.com
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.adyen.model.legalentitymanagement;

import java.util.Objects;
import java.util.Arrays;
import com.google.gson.TypeAdapter;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import java.io.IOException;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.TypeAdapterFactory;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import com.adyen.model.legalentitymanagement.JSON;

/**
 * AcceptTermsOfServiceResponse
 */

public class AcceptTermsOfServiceResponse {
  public static final String SERIALIZED_NAME_ACCEPTED_BY = "acceptedBy";
  @SerializedName(SERIALIZED_NAME_ACCEPTED_BY)
  private String acceptedBy;

  public static final String SERIALIZED_NAME_ID = "id";
  @SerializedName(SERIALIZED_NAME_ID)
  private String id;

  public static final String SERIALIZED_NAME_IP_ADDRESS = "ipAddress";
  @SerializedName(SERIALIZED_NAME_IP_ADDRESS)
  private String ipAddress;

  public static final String SERIALIZED_NAME_LANGUAGE = "language";
  @SerializedName(SERIALIZED_NAME_LANGUAGE)
  private String language;

  public static final String SERIALIZED_NAME_TERMS_OF_SERVICE_DOCUMENT_ID = "termsOfServiceDocumentId";
  @SerializedName(SERIALIZED_NAME_TERMS_OF_SERVICE_DOCUMENT_ID)
  private String termsOfServiceDocumentId;

  /**
   * The type of Terms of Service.
   */
  @JsonAdapter(TypeEnum.Adapter.class)
  public enum TypeEnum {
    ADYENACCOUNT("adyenAccount"),
    
    ADYENCAPITAL("adyenCapital"),
    
    ADYENCARD("adyenCard"),
    
    ADYENFORPLATFORMSADVANCED("adyenForPlatformsAdvanced"),
    
    ADYENFORPLATFORMSMANAGE("adyenForPlatformsManage"),
    
    ADYENFRANCHISEE("adyenFranchisee"),
    
    ADYENISSUING("adyenIssuing");

    private String value;

    TypeEnum(String value) {
      this.value = value;
    }

    public String getValue() {
      return value;
    }

    @Override
    public String toString() {
      return String.valueOf(value);
    }

    public static TypeEnum fromValue(String value) {
      for (TypeEnum b : TypeEnum.values()) {
        if (b.value.equals(value)) {
          return b;
        }
      }
      throw new IllegalArgumentException("Unexpected value '" + value + "'");
    }

    public static class Adapter extends TypeAdapter<TypeEnum> {
      @Override
      public void write(final JsonWriter jsonWriter, final TypeEnum enumeration) throws IOException {
        jsonWriter.value(enumeration.getValue());
      }

      @Override
      public TypeEnum read(final JsonReader jsonReader) throws IOException {
        String value =  jsonReader.nextString();
        return TypeEnum.fromValue(value);
      }
    }
  }

  public static final String SERIALIZED_NAME_TYPE = "type";
  @SerializedName(SERIALIZED_NAME_TYPE)
  private TypeEnum type;

  public AcceptTermsOfServiceResponse() { 
  }

  public AcceptTermsOfServiceResponse acceptedBy(String acceptedBy) {
    
    this.acceptedBy = acceptedBy;
    return this;
  }

   /**
   * The unique identifier of the user that accepted the Terms of Service.
   * @return acceptedBy
  **/
  @ApiModelProperty(value = "The unique identifier of the user that accepted the Terms of Service.")

  public String getAcceptedBy() {
    return acceptedBy;
  }


  public void setAcceptedBy(String acceptedBy) {
    this.acceptedBy = acceptedBy;
  }


  public AcceptTermsOfServiceResponse id(String id) {
    
    this.id = id;
    return this;
  }

   /**
   * The unique identifier of the Terms of Service acceptance.
   * @return id
  **/
  @ApiModelProperty(value = "The unique identifier of the Terms of Service acceptance.")

  public String getId() {
    return id;
  }


  public void setId(String id) {
    this.id = id;
  }


  public AcceptTermsOfServiceResponse ipAddress(String ipAddress) {
    
    this.ipAddress = ipAddress;
    return this;
  }

   /**
   * The IP address of the user that accepted the Terms of Service.
   * @return ipAddress
  **/
  @ApiModelProperty(value = "The IP address of the user that accepted the Terms of Service.")

  public String getIpAddress() {
    return ipAddress;
  }


  public void setIpAddress(String ipAddress) {
    this.ipAddress = ipAddress;
  }


  public AcceptTermsOfServiceResponse language(String language) {
    
    this.language = language;
    return this;
  }

   /**
   * The language used for the Terms of Service document, specified by the two letter [ISO 639-1](https://en.wikipedia.org/wiki/List_of_ISO_639-1_codes) language code. For example, **nl** for Dutch.
   * @return language
  **/
  @ApiModelProperty(value = "The language used for the Terms of Service document, specified by the two letter [ISO 639-1](https://en.wikipedia.org/wiki/List_of_ISO_639-1_codes) language code. For example, **nl** for Dutch.")

  public String getLanguage() {
    return language;
  }


  public void setLanguage(String language) {
    this.language = language;
  }


  public AcceptTermsOfServiceResponse termsOfServiceDocumentId(String termsOfServiceDocumentId) {
    
    this.termsOfServiceDocumentId = termsOfServiceDocumentId;
    return this;
  }

   /**
   * The unique identifier of the Terms of Service document.
   * @return termsOfServiceDocumentId
  **/
  @ApiModelProperty(value = "The unique identifier of the Terms of Service document.")

  public String getTermsOfServiceDocumentId() {
    return termsOfServiceDocumentId;
  }


  public void setTermsOfServiceDocumentId(String termsOfServiceDocumentId) {
    this.termsOfServiceDocumentId = termsOfServiceDocumentId;
  }


  public AcceptTermsOfServiceResponse type(TypeEnum type) {
    
    this.type = type;
    return this;
  }

   /**
   * The type of Terms of Service.
   * @return type
  **/
  @ApiModelProperty(value = "The type of Terms of Service.")

  public TypeEnum getType() {
    return type;
  }


  public void setType(TypeEnum type) {
    this.type = type;
  }



  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    AcceptTermsOfServiceResponse acceptTermsOfServiceResponse = (AcceptTermsOfServiceResponse) o;
    return Objects.equals(this.acceptedBy, acceptTermsOfServiceResponse.acceptedBy) &&
        Objects.equals(this.id, acceptTermsOfServiceResponse.id) &&
        Objects.equals(this.ipAddress, acceptTermsOfServiceResponse.ipAddress) &&
        Objects.equals(this.language, acceptTermsOfServiceResponse.language) &&
        Objects.equals(this.termsOfServiceDocumentId, acceptTermsOfServiceResponse.termsOfServiceDocumentId) &&
        Objects.equals(this.type, acceptTermsOfServiceResponse.type);
  }

  @Override
  public int hashCode() {
    return Objects.hash(acceptedBy, id, ipAddress, language, termsOfServiceDocumentId, type);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class AcceptTermsOfServiceResponse {\n");
    sb.append("    acceptedBy: ").append(toIndentedString(acceptedBy)).append("\n");
    sb.append("    id: ").append(toIndentedString(id)).append("\n");
    sb.append("    ipAddress: ").append(toIndentedString(ipAddress)).append("\n");
    sb.append("    language: ").append(toIndentedString(language)).append("\n");
    sb.append("    termsOfServiceDocumentId: ").append(toIndentedString(termsOfServiceDocumentId)).append("\n");
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


  public static HashSet<String> openapiFields;
  public static HashSet<String> openapiRequiredFields;

  static {
    // a set of all properties/fields (JSON key names)
    openapiFields = new HashSet<String>();
    openapiFields.add("acceptedBy");
    openapiFields.add("id");
    openapiFields.add("ipAddress");
    openapiFields.add("language");
    openapiFields.add("termsOfServiceDocumentId");
    openapiFields.add("type");

    // a set of required properties/fields (JSON key names)
    openapiRequiredFields = new HashSet<String>();
  }

 /**
  * Validates the JSON Object and throws an exception if issues found
  *
  * @param jsonObj JSON Object
  * @throws IOException if the JSON Object is invalid with respect to AcceptTermsOfServiceResponse
  */
  public static void validateJsonObject(JsonObject jsonObj) throws IOException {
      if (jsonObj == null) {
        if (AcceptTermsOfServiceResponse.openapiRequiredFields.isEmpty()) {
          return;
        } else { // has required fields
          throw new IllegalArgumentException(String.format("The required field(s) %s in AcceptTermsOfServiceResponse is not found in the empty JSON string", AcceptTermsOfServiceResponse.openapiRequiredFields.toString()));
        }
      }

      Set<Entry<String, JsonElement>> entries = jsonObj.entrySet();
      // check to see if the JSON string contains additional fields
      for (Entry<String, JsonElement> entry : entries) {
        if (!AcceptTermsOfServiceResponse.openapiFields.contains(entry.getKey())) {
          throw new IllegalArgumentException(String.format("The field `%s` in the JSON string is not defined in the `AcceptTermsOfServiceResponse` properties. JSON: %s", entry.getKey(), jsonObj.toString()));
        }
      }
      // validate the optional field acceptedBy
      if (jsonObj.get("acceptedBy") != null && !jsonObj.get("acceptedBy").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `acceptedBy` to be a primitive type in the JSON string but got `%s`", jsonObj.get("acceptedBy").toString()));
      }
      // validate the optional field id
      if (jsonObj.get("id") != null && !jsonObj.get("id").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `id` to be a primitive type in the JSON string but got `%s`", jsonObj.get("id").toString()));
      }
      // validate the optional field ipAddress
      if (jsonObj.get("ipAddress") != null && !jsonObj.get("ipAddress").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `ipAddress` to be a primitive type in the JSON string but got `%s`", jsonObj.get("ipAddress").toString()));
      }
      // validate the optional field language
      if (jsonObj.get("language") != null && !jsonObj.get("language").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `language` to be a primitive type in the JSON string but got `%s`", jsonObj.get("language").toString()));
      }
      // validate the optional field termsOfServiceDocumentId
      if (jsonObj.get("termsOfServiceDocumentId") != null && !jsonObj.get("termsOfServiceDocumentId").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `termsOfServiceDocumentId` to be a primitive type in the JSON string but got `%s`", jsonObj.get("termsOfServiceDocumentId").toString()));
      }
      // ensure the field type can be parsed to an enum value
      if (jsonObj.get("type") != null) {
        if(!jsonObj.get("type").isJsonPrimitive()) {
          throw new IllegalArgumentException(String.format("Expected the field `type` to be a primitive type in the JSON string but got `%s`", jsonObj.get("type").toString()));
        }
        TypeEnum.fromValue(jsonObj.get("type").getAsString());
      }
  }

  public static class CustomTypeAdapterFactory implements TypeAdapterFactory {
    @SuppressWarnings("unchecked")
    @Override
    public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
       if (!AcceptTermsOfServiceResponse.class.isAssignableFrom(type.getRawType())) {
         return null; // this class only serializes 'AcceptTermsOfServiceResponse' and its subtypes
       }
       final TypeAdapter<JsonElement> elementAdapter = gson.getAdapter(JsonElement.class);
       final TypeAdapter<AcceptTermsOfServiceResponse> thisAdapter
                        = gson.getDelegateAdapter(this, TypeToken.get(AcceptTermsOfServiceResponse.class));

       return (TypeAdapter<T>) new TypeAdapter<AcceptTermsOfServiceResponse>() {
           @Override
           public void write(JsonWriter out, AcceptTermsOfServiceResponse value) throws IOException {
             JsonObject obj = thisAdapter.toJsonTree(value).getAsJsonObject();
             elementAdapter.write(out, obj);
           }

           @Override
           public AcceptTermsOfServiceResponse read(JsonReader in) throws IOException {
             JsonObject jsonObj = elementAdapter.read(in).getAsJsonObject();
             validateJsonObject(jsonObj);
             return thisAdapter.fromJsonTree(jsonObj);
           }

       }.nullSafe();
    }
  }

 /**
  * Create an instance of AcceptTermsOfServiceResponse given an JSON string
  *
  * @param jsonString JSON string
  * @return An instance of AcceptTermsOfServiceResponse
  * @throws IOException if the JSON string is invalid with respect to AcceptTermsOfServiceResponse
  */
  public static AcceptTermsOfServiceResponse fromJson(String jsonString) throws IOException {
    return JSON.getGson().fromJson(jsonString, AcceptTermsOfServiceResponse.class);
  }

 /**
  * Convert an instance of AcceptTermsOfServiceResponse to an JSON string
  *
  * @return JSON string
  */
  public String toJson() {
    return JSON.getGson().toJson(this);
  }
}
