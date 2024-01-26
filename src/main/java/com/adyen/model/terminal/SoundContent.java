/*
 * Adyen Terminal API
 *
 * The version of the OpenAPI document: 1
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.adyen.model.terminal;

import java.util.Objects;
import java.util.Arrays;
import java.util.Map;
import java.util.HashMap;
import com.adyen.model.terminal.SoundFormat;
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
 * SoundContent
 */
@JsonPropertyOrder({
  SoundContent.JSON_PROPERTY_SOUND_FORMAT,
  SoundContent.JSON_PROPERTY_LANGUAGE,
  SoundContent.JSON_PROPERTY_REFERENCE_I_D,
  SoundContent.JSON_PROPERTY_TEXT
})

public class SoundContent {
  public static final String JSON_PROPERTY_SOUND_FORMAT = "SoundFormat";
  private SoundFormat soundFormat;

  public static final String JSON_PROPERTY_LANGUAGE = "Language";
  private String language;

  public static final String JSON_PROPERTY_REFERENCE_I_D = "ReferenceID";
  private String referenceID;

  public static final String JSON_PROPERTY_TEXT = "Text";
  private String text;

  public SoundContent() { 
  }

  public SoundContent soundFormat(SoundFormat soundFormat) {
    this.soundFormat = soundFormat;
    return this;
  }

   /**
   * Get soundFormat
   * @return soundFormat
  **/
  @ApiModelProperty(required = true, value = "")
  @JsonProperty(JSON_PROPERTY_SOUND_FORMAT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public SoundFormat getSoundFormat() {
    return soundFormat;
  }


 /**
  * soundFormat
  *
  * @param soundFormat
  */ 
  @JsonProperty(JSON_PROPERTY_SOUND_FORMAT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setSoundFormat(SoundFormat soundFormat) {
    this.soundFormat = soundFormat;
  }


  public SoundContent language(String language) {
    this.language = language;
    return this;
  }

   /**
   * Get language
   * @return language
  **/
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_LANGUAGE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getLanguage() {
    return language;
  }


 /**
  * language
  *
  * @param language
  */ 
  @JsonProperty(JSON_PROPERTY_LANGUAGE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setLanguage(String language) {
    this.language = language;
  }


  public SoundContent referenceID(String referenceID) {
    this.referenceID = referenceID;
    return this;
  }

   /**
   * Get referenceID
   * @return referenceID
  **/
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_REFERENCE_I_D)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getReferenceID() {
    return referenceID;
  }


 /**
  * referenceID
  *
  * @param referenceID
  */ 
  @JsonProperty(JSON_PROPERTY_REFERENCE_I_D)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setReferenceID(String referenceID) {
    this.referenceID = referenceID;
  }


  public SoundContent text(String text) {
    this.text = text;
    return this;
  }

   /**
   * Get text
   * @return text
  **/
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_TEXT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getText() {
    return text;
  }


 /**
  * text
  *
  * @param text
  */ 
  @JsonProperty(JSON_PROPERTY_TEXT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setText(String text) {
    this.text = text;
  }


  /**
   * Return true if this SoundContent object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    SoundContent soundContent = (SoundContent) o;
    return Objects.equals(this.soundFormat, soundContent.soundFormat) &&
        Objects.equals(this.language, soundContent.language) &&
        Objects.equals(this.referenceID, soundContent.referenceID) &&
        Objects.equals(this.text, soundContent.text);
  }

  @Override
  public int hashCode() {
    return Objects.hash(soundFormat, language, referenceID, text);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class SoundContent {\n");
    sb.append("    soundFormat: ").append(toIndentedString(soundFormat)).append("\n");
    sb.append("    language: ").append(toIndentedString(language)).append("\n");
    sb.append("    referenceID: ").append(toIndentedString(referenceID)).append("\n");
    sb.append("    text: ").append(toIndentedString(text)).append("\n");
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
   * Create an instance of SoundContent given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of SoundContent
   * @throws JsonProcessingException if the JSON string is invalid with respect to SoundContent
   */
  public static SoundContent fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, SoundContent.class);
  }
/**
  * Convert an instance of SoundContent to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}
