package com.microsoft.identity.common.java.commands.parameters.nativeauth;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NonNull;
import lombok.experimental.SuperBuilder;

@Getter
@EqualsAndHashCode(callSuper = true)
@SuperBuilder(toBuilder = true)
public class BaseSignInStartCommandParameters extends BaseSignInTokenCommandParameters {
   private static final String TAG = BaseSignInStartCommandParameters.class.getSimpleName();

   @NonNull
   public final String username;
}