package com.microsoft.identity.common.internal.commands.parameters;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.experimental.SuperBuilder;

@Getter
@EqualsAndHashCode(callSuper = true)
@SuperBuilder(toBuilder = true)
public class SignUpChallengeCommandParameters extends BaseNativeAuthCommandParameters {
	private static final String TAG = SignUpChallengeCommandParameters.class.getSimpleName();
}

