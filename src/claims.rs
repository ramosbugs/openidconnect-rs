use std::fmt::{Debug, Formatter, Result as FormatterResult};
use std::marker::PhantomData;
use std::str;

use chrono::{DateTime, Utc};
use serde;
use serde::de::{Deserialize, DeserializeOwned, Deserializer, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};

use super::types::helpers::{seconds_to_utc, split_language_tag_key, utc_to_seconds};
use super::types::{LocalizedClaim, Seconds};
use super::{
    AddressCountry, AddressLocality, AddressPostalCode, AddressRegion, EndUserBirthday,
    EndUserEmail, EndUserFamilyName, EndUserGivenName, EndUserMiddleName, EndUserName,
    EndUserNickname, EndUserPhoneNumber, EndUserPictureUrl, EndUserProfileUrl, EndUserTimezone,
    EndUserUsername, EndUserWebsiteUrl, FormattedAddress, LanguageTag, StreetAddress,
    SubjectIdentifier,
};

pub trait AdditionalClaims:
    Clone + Debug + DeserializeOwned + PartialEq + Serialize + 'static
{
}

// In order to support serde flatten, this must be an empty struct rather than an empty
// tuple struct.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct EmptyAdditionalClaims {}
impl AdditionalClaims for EmptyAdditionalClaims {}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct AddressClaim {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted: Option<FormattedAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub street_address: Option<StreetAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locality: Option<AddressLocality>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<AddressRegion>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<AddressPostalCode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<AddressCountry>,
}

pub trait GenderClaim: Clone + Debug + DeserializeOwned + PartialEq + Serialize + 'static {}

// Private (fields accessed via IdTokenClaims and UserInfoClaims)
#[derive(Clone, Debug, PartialEq)]
pub struct StandardClaims<GC>
where
    GC: GenderClaim,
{
    pub sub: SubjectIdentifier,
    pub name: Option<LocalizedClaim<EndUserName>>,
    pub given_name: Option<LocalizedClaim<EndUserGivenName>>,
    pub family_name: Option<LocalizedClaim<EndUserFamilyName>>,
    pub middle_name: Option<LocalizedClaim<EndUserMiddleName>>,
    pub nickname: Option<LocalizedClaim<EndUserNickname>>,
    pub preferred_username: Option<EndUserUsername>,
    pub profile: Option<LocalizedClaim<EndUserProfileUrl>>,
    pub picture: Option<LocalizedClaim<EndUserPictureUrl>>,
    pub website: Option<LocalizedClaim<EndUserWebsiteUrl>>,
    pub email: Option<EndUserEmail>,
    pub email_verified: Option<bool>,
    pub gender: Option<GC>,
    pub birthday: Option<EndUserBirthday>,
    pub zoneinfo: Option<EndUserTimezone>,
    pub locale: Option<LanguageTag>,
    pub phone_number: Option<EndUserPhoneNumber>,
    pub phone_number_verified: Option<bool>,
    pub address: Option<AddressClaim>,
    pub updated_at: Option<DateTime<Utc>>,
}
impl<GC> StandardClaims<GC>
where
    GC: GenderClaim,
{
    pub fn new(sub: SubjectIdentifier) -> Self {
        Self {
            sub,
            name: None,
            given_name: None,
            family_name: None,
            middle_name: None,
            nickname: None,
            preferred_username: None,
            profile: None,
            picture: None,
            website: None,
            email: None,
            email_verified: None,
            gender: None,
            birthday: None,
            zoneinfo: None,
            locale: None,
            phone_number: None,
            phone_number_verified: None,
            address: None,
            updated_at: None,
        }
    }
}
impl<'de, GC> Deserialize<'de> for StandardClaims<GC>
where
    GC: GenderClaim,
{
    ///
    /// Special deserializer that supports [RFC 5646](https://tools.ietf.org/html/rfc5646) language
    /// tags associated with human-readable client metadata fields.
    ///
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ClaimsVisitor<GC: GenderClaim>(PhantomData<GC>);
        impl<'de, GC> Visitor<'de> for ClaimsVisitor<GC>
        where
            GC: GenderClaim,
        {
            type Value = StandardClaims<GC>;

            fn expecting(&self, formatter: &mut Formatter) -> FormatterResult {
                formatter.write_str("struct StandardClaims")
            }
            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                deserialize_fields! {
                    map {
                        [sub]
                        [LanguageTag(name)]
                        [LanguageTag(given_name)]
                        [LanguageTag(family_name)]
                        [LanguageTag(middle_name)]
                        [LanguageTag(nickname)]
                        [Option(preferred_username)]
                        [LanguageTag(profile)]
                        [LanguageTag(picture)]
                        [LanguageTag(website)]
                        [Option(email)]
                        [Option(email_verified)]
                        [Option(gender)]
                        [Option(birthday)]
                        [Option(zoneinfo)]
                        [Option(locale)]
                        [Option(phone_number)]
                        [Option(phone_number_verified)]
                        [Option(address)]
                        [Option(DateTime(Seconds(updated_at)))]
                    }
                }
            }
        }
        deserializer.deserialize_map(ClaimsVisitor(PhantomData))
    }
}
impl<GC> Serialize for StandardClaims<GC>
where
    GC: GenderClaim,
{
    #[allow(clippy::cognitive_complexity)]
    fn serialize<SE>(&self, serializer: SE) -> Result<SE::Ok, SE::Error>
    where
        SE: Serializer,
    {
        serialize_fields! {
            self -> serializer {
                [sub]
                [LanguageTag(name)]
                [LanguageTag(given_name)]
                [LanguageTag(family_name)]
                [LanguageTag(middle_name)]
                [LanguageTag(nickname)]
                [Option(preferred_username)]
                [LanguageTag(profile)]
                [LanguageTag(picture)]
                [LanguageTag(website)]
                [Option(email)]
                [Option(email_verified)]
                [Option(gender)]
                [Option(birthday)]
                [Option(zoneinfo)]
                [Option(locale)]
                [Option(phone_number)]
                [Option(phone_number_verified)]
                [Option(address)]
                [Option(DateTime(Seconds(updated_at)))]
            }
        }
    }
}
