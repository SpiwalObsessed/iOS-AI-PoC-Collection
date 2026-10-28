## UnifiedAssetFramework

> `/System/Library/PrivateFrameworks/UnifiedAssetFramework.framework/UnifiedAssetFramework`

```diff

-3600.77.1.0.0
-  __TEXT.__text: 0x77d94
-  __TEXT.__objc_methlist: 0x36d8
-  __TEXT.__const: 0x190
+3605.17.1.0.0
+  __TEXT.__text: 0x76f10
+  __TEXT.__objc_methlist: 0x3690
+  __TEXT.__const: 0x198
   __TEXT.__constg_swiftt: 0x48
   __TEXT.__swift5_typeref: 0x67
   __TEXT.__swift5_reflstr: 0x9
   __TEXT.__swift5_fieldmd: 0x1c
-  __TEXT.__cstring: 0xb871
-  __TEXT.__oslogstring: 0xee16
+  __TEXT.__cstring: 0xb7c6
+  __TEXT.__oslogstring: 0xf0c7
   __TEXT.__swift5_types: 0x4
-  __TEXT.__gcc_except_tab: 0xe08
-  __TEXT.__unwind_info: 0x1200
+  __TEXT.__gcc_except_tab: 0xe0c
+  __TEXT.__unwind_info: 0x1220
   __TEXT.__objc_stubs: 0x0
   __TEXT.__auth_stubs: 0x0
   __TEXT.__objc_classname: 0x0
   __TEXT.__objc_methname: 0x0
   __TEXT.__objc_methtype: 0x0
   __DATA_CONST.__const: 0x1d10
-  __DATA_CONST.__objc_classlist: 0x1b8
+  __DATA_CONST.__objc_classlist: 0x1b0
   __DATA_CONST.__objc_protolist: 0x28
   __DATA_CONST.__objc_imageinfo: 0x8
-  __DATA_CONST.__objc_selrefs: 0x26b0
+  __DATA_CONST.__objc_selrefs: 0x2630
   __DATA_CONST.__objc_protorefs: 0x8
   __DATA_CONST.__objc_superrefs: 0xf0
-  __DATA_CONST.__objc_arraydata: 0x130
-  __DATA_CONST.__got: 0x5c0
-  __AUTH_CONST.__const: 0x5c8
-  __AUTH_CONST.__cfstring: 0x51c0
-  __AUTH_CONST.__objc_const: 0x46c0
+  __DATA_CONST.__objc_arraydata: 0x128
+  __DATA_CONST.__got: 0x550
+  __AUTH_CONST.__const: 0x608
+  __AUTH_CONST.__cfstring: 0x5520
+  __AUTH_CONST.__objc_const: 0x4630
   __AUTH_CONST.__objc_arrayobj: 0x90
-  __AUTH_CONST.__objc_intobj: 0x228
+  __AUTH_CONST.__objc_intobj: 0x1f8
   __AUTH_CONST.__objc_dictobj: 0x50
-  __AUTH_CONST.__auth_got: 0x890
+  __AUTH_CONST.__auth_got: 0x8a0
   __AUTH_CONST.__auth_ptr: 0x0
-  __AUTH.__objc_data: 0x6b0
-  __AUTH.__data: 0xc8
+  __AUTH.__objc_data: 0x98
   __DATA.__objc_ivar: 0x320
-  __DATA.__data: 0x2c0
+  __DATA.__data: 0x298
   __DATA.__bss: 0x38
   __DATA.__common: 0x8
-  __DATA_DIRTY.__objc_data: 0xa50
-  __DATA_DIRTY.__bss: 0x250
+  __DATA_DIRTY.__objc_data: 0x1018
+  __DATA_DIRTY.__data: 0xc8
+  __DATA_DIRTY.__bss: 0x278
   __DATA_DIRTY.__common: 0x68
   - /System/Library/Frameworks/CoreFoundation.framework/CoreFoundation
   - /System/Library/Frameworks/Foundation.framework/Foundation

   - /usr/lib/swift/libswiftXPC.dylib
   - /usr/lib/swift/libswift_Builtin_float.dylib
   - /usr/lib/swift/libswiftos.dylib
-  Functions: 1460
-  Symbols:   3783
+  Functions: 1457
+  Symbols:   3744
   CStrings:  0
 
Symbols:
+ +[UAFAssetOriginReport absentAttributesForEntry:]
+ +[UAFAutoAssetManager getDownloadStatusesFromAssetSetUsages:configurationManager:]
+ +[UAFAutoAssetManager listenForEliminates:updateHandler:]
+ +[UAFAutoAssetManager populateAlterTelemetry:status:addedSpecifiers:removedSpecifiers:]
+ +[UAFAutoAssetManager registerNotification:queue:updateHandler:]
+ +[UAFAutoAssetManager shouldEmitAlterForPSUSStatus:]
+ +[UAFAutoBugCapture captureWithType:subType:context:logCategory:pid:]
+ +[UAFAutoBugCapture captureWithType:subType:context:logCategory:pid:withSDRDiagnosticReporter:]
+ +[UAFCommonUtilities nameForPid:]
+ +[UAFCommonUtilities pathFromRealpath:]
+ +[UAFCommonUtilities urlFromRealpath:]
+ -[UAFAssetOriginReport _logSummaryForTotal:unrecorded:partial:]
+ -[UAFAssetSetManager downloadStatusesForSubscribers:]
+ -[UAFSubscriptionStoreManager _getAllSubscriptionsFlat:]
+ -[UAFSubscriptionStoreManager _readSystemConfigurationForKey:value:]
+ GCC_except_table102
+ GCC_except_table103
+ GCC_except_table109
+ GCC_except_table118
+ GCC_except_table127
+ GCC_except_table134
+ GCC_except_table151
+ GCC_except_table53
+ GCC_except_table55
+ GCC_except_table58
+ GCC_except_table65
+ GCC_except_table72
+ GCC_except_table76
+ GCC_except_table88
+ GCC_except_table95
+ _OBJC_CLASS_$_NSNull
+ ___39+[UAFAutoAssetManager observeAssetSet:]_block_invoke_2
+ ___45-[UAFAssetSetSubscription expirationAsString]_block_invoke
+ ___53-[UAFAssetSetManager downloadStatusesForSubscribers:]_block_invoke
+ ___54+[UAFAutoAssetManager logAtomicInstance:name:entries:]_block_invoke_2
+ ___64+[UAFAutoAssetManager registerNotification:queue:updateHandler:]_block_invoke
+ ___64+[UAFCommonUtilities getISO8601Timestamp:withFractionalSeconds:]_block_invoke
+ _objc_msgSend$_getAllSubscriptionsFlat:
+ _objc_msgSend$_logSummaryForTotal:unrecorded:partial:
+ _objc_msgSend$_readSystemConfigurationForKey:value:
+ _objc_msgSend$absentAttributesForEntry:
+ _objc_msgSend$captureWithType:subType:context:logCategory:pid:
+ _objc_msgSend$captureWithType:subType:context:logCategory:pid:withSDRDiagnosticReporter:
+ _objc_msgSend$componentsJoinedByString:
+ _objc_msgSend$getDownloadStatusesFromAssetSetUsages:configurationManager:
+ _objc_msgSend$isLatestDownloadedFreshForCurrentOSWithError:
+ _objc_msgSend$latestDownloadedAtomicInstanceFreshnessFromBuildVersion
+ _objc_msgSend$latestDownloadedAtomicInstanceFreshnessFromOSVersion
+ _objc_msgSend$listenForEliminates:updateHandler:
+ _objc_msgSend$nameForPid:
+ _objc_msgSend$null
+ _objc_msgSend$pathFromRealpath:
+ _objc_msgSend$populateAlterTelemetry:status:addedSpecifiers:removedSpecifiers:
+ _objc_msgSend$registerNotification:queue:updateHandler:
+ _objc_msgSend$setAssets:
+ _objc_msgSend$setFormatOptions:
+ _objc_msgSend$shouldEmitAlterForPSUSStatus:
+ _objc_retain_x9
+ _realpath$DARWIN_EXTSN
+ _sysctl
- +[UAFAutoBugCapture captureWithType:subType:context:logCategory:]
- +[UAFAutoBugCapture captureWithType:subType:context:logCategory:withSDRDiagnosticReporter:]
- +[UAFBiomeInstrumenter _constructBiomeAssetSet:storeManager:]
- +[UAFBiomeInstrumenter _createBiomeAssetSet:withAssets:sourceType:]
- +[UAFBiomeInstrumenter _getAssetOriginType:]
- +[UAFBiomeInstrumenter _getAssetSource:]
- +[UAFBiomeInstrumenter _getBiomeAssetSetStatus:atomicInstanceMetadata:assetSetOriginReport:entries:errorCodes:]
- +[UAFBiomeInstrumenter _getBiomeEventDeviceMetadata]
- +[UAFBiomeInstrumenter _getBiomeStreamForAssetSetStatus:atomicInstanceMetadata:assetSetOriginReport:entries:errorCodes:assetSetDailyStatusEventType:]
- +[UAFBiomeInstrumenter _getBiomeStreamForScheduledDailyAssetStatus]
- +[UAFBiomeInstrumenter _getBiomeUAFAssetSet:atomicInstanceMetadata:assetSetOriginReport:entries:errorCodes:]
- +[UAFBiomeInstrumenter _getSubscriptionsStatus]
- +[UAFBiomeInstrumenter defaultDeviceId]
- +[UAFBiomeInstrumenter isBiomeAvailable]
- +[UAFBiomeInstrumenter logAlterFromAtomicInstance:sourceType:addedAssets:removedAssets:]
- +[UAFBiomeInstrumenter logAssetSetDownloadEvent:atomicInstanceMetadata:entries:errorCodes:assetOriginReport:assetSetDailyStatusEventType:]
- +[UAFBiomeInstrumenter logScheduledDailyAssetStatus]
- +[UAFCommonUtilities pathByResolvingSymlinksButKeepingPrivatePrefix:]
- +[UAFCommonUtilities urlByResolvingSymlinksButKeepingPrivatePrefix:]
- GCC_except_table107
- GCC_except_table111
- GCC_except_table120
- GCC_except_table149
- GCC_except_table52
- GCC_except_table54
- GCC_except_table64
- GCC_except_table71
- GCC_except_table75
- GCC_except_table77
- GCC_except_table87
- GCC_except_table96
- GCC_except_table99
- _OBJC_CLASS_$_BMAssetDeliveryDailyStatus
- _OBJC_CLASS_$_BMUAFAsset
- _OBJC_CLASS_$_BMUAFAssetSet
- _OBJC_CLASS_$_BMUAFAssetSetStatus
- _OBJC_CLASS_$_BMUAFAssetSetSubscription
- _OBJC_CLASS_$_BMUAFAssetSetUsage
- _OBJC_CLASS_$_BMUAFAssetSubscriberSubscriptions
- _OBJC_CLASS_$_BMUAFAssetUsageAlias
- _OBJC_CLASS_$_BMUAFAvailableAssetDailyStatus
- _OBJC_CLASS_$_BMUAFDeviceMetadata
- _OBJC_CLASS_$_BMUAFISOLocale
- _OBJC_CLASS_$_BMUAFMobileAssetDownloadErrorCodeFrequency
- _OBJC_CLASS_$_NSDateFormatter
- _OBJC_CLASS_$_NSLocale
- _OBJC_CLASS_$_UAFBiomeInstrumenter
- _OBJC_METACLASS_$_UAFBiomeInstrumenter
- __OBJC_$_CLASS_METHODS_UAFBiomeInstrumenter
- __OBJC_CLASS_RO_$_UAFBiomeInstrumenter
- __OBJC_METACLASS_RO_$_UAFBiomeInstrumenter
- ___39+[UAFBiomeInstrumenter defaultDeviceId]_block_invoke
- ___47+[UAFBiomeInstrumenter _getSubscriptionsStatus]_block_invoke
- ___54+[UAFAutoAssetManager listenForUpdates:updateHandler:]_block_invoke
- _kUAFABCAssetSourceUknownFailure
- _kUAFABCInstanceFailure
- _kUAFABCInstrumentationFailure
- _kUAFABCMissingAvailableOSBuildFailure
- _kUAFABCMissingDownloadedOSBuildFailure
- _objc_msgSend$DailyStatus
- _objc_msgSend$UUIDString
- _objc_msgSend$_createBiomeAssetSet:withAssets:sourceType:
- _objc_msgSend$_getBiomeAssetSetStatus:atomicInstanceMetadata:assetSetOriginReport:entries:errorCodes:
- _objc_msgSend$_getBiomeEventDeviceMetadata
- _objc_msgSend$_getBiomeStreamForAssetSetStatus:atomicInstanceMetadata:assetSetOriginReport:entries:errorCodes:assetSetDailyStatusEventType:
- _objc_msgSend$_getBiomeStreamForScheduledDailyAssetStatus
- _objc_msgSend$_getSubscriptionsStatus
- _objc_msgSend$autoAssetSet
- _objc_msgSend$buildVersion
- _objc_msgSend$captureWithType:subType:context:logCategory:
- _objc_msgSend$captureWithType:subType:context:logCategory:withSDRDiagnosticReporter:
- _objc_msgSend$countForObject:
- _objc_msgSend$currentLocale
- _objc_msgSend$defaultDeviceId
- _objc_msgSend$getMAAutoAssetDownloadErrorsSync
- _objc_msgSend$initWithAliasName:aliasValue:
- _objc_msgSend$initWithAssetName:assetSpecifier:assetVersion:assetLocale:assetSource:isAssetPathValid:assetPath:assetDownloadSizeInBytes:assetUnarchivedSizeInBytes:sourceOSBuild:promotedOSBuild:
- _objc_msgSend$initWithAssetSetName:assets:assetType:assetSetId:audienceId:mobileAssetDownloadErrorCodeFrequency:fromPreSoftwareUpdateStaging:expensiveCellularDownloadRequested:fromFactory:
- _objc_msgSend$initWithAssetSetStatus:statusReason:
- _objc_msgSend$initWithDeviceId:deviceType:programCode:systemBuild:inputLocale:nanoSecondsSinceLastBoot:
- _objc_msgSend$initWithDeviceMetadata:availableAssetDailyStatus:
- _objc_msgSend$initWithLanguageCode:countryCode:
- _objc_msgSend$initWithMobileAssetDownloadErrorCode:timesOccurred:
- _objc_msgSend$initWithSubscriberName:subscriptions:
- _objc_msgSend$initWithSubscriptionName:assetSetIndices:assetSetUsages:usageAliases:alteredAssetSets:eliminatedAssetSets:
- _objc_msgSend$initWithUafAssetSets:uafAssetSubscriptions:allAssets:
- _objc_msgSend$initWithUsageName:usageValue:
- _objc_msgSend$isBiomeAvailable
- _objc_msgSend$languageCode
- _objc_msgSend$logAlterFromAtomicInstance:sourceType:addedAssets:removedAssets:
- _objc_msgSend$logAssetSetDownloadEvent:atomicInstanceMetadata:entries:errorCodes:assetOriginReport:assetSetDailyStatusEventType:
- _objc_msgSend$pathByResolvingSymlinksButKeepingPrivatePrefix:
- _objc_msgSend$regionCode
- _objc_msgSend$setDateFormat:
- _objc_msgSend$stringByResolvingSymlinksInPath
- _objc_msgSend$stringForKey:
- _objc_msgSend$stringFromDate:timeZone:formatOptions:
- _objc_msgSend$synchronize
- _objc_retain_x6
```
