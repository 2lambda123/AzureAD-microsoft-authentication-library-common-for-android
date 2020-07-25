package com.microsoft.identity.client.ui.automation.rules;

import android.util.Log;

import com.microsoft.identity.client.ui.automation.annotations.RetryOnFailure;

import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;

/**
 * A Test Rule to retry the test n number of times where n could be any number as denoted by the
 * {@link RetryOnFailure} annotation
 */
public class RetryTestRule implements TestRule {

    private final static String TAG = RetryTestRule.class.getSimpleName();

    @Override
    public Statement apply(final Statement base, final Description description) {
        return new Statement() {
            @Override
            public void evaluate() throws Throwable {
                Throwable caughtThrowable = null;
                int numAttempts = 1;

                RetryOnFailure retryOnFailure = description.getAnnotation(RetryOnFailure.class);

                if (retryOnFailure == null) {
                    // if the test didn't have the RetryOnFailure annotation, then we see if the
                    // class had that annotation and we try to honor that
                    retryOnFailure = description.getTestClass().getAnnotation(RetryOnFailure.class);
                }

                if (retryOnFailure != null) {
                    final int retryCount = retryOnFailure.retryCount();
                    Log.i(TAG, "Received retry count annotation with value: " + retryCount);
                    numAttempts += retryCount;
                }

                for (int i = 0; i < numAttempts; i++) {
                    try {
                        Log.i(TAG, "Executing attempt #" + (i + 1) + " of " + numAttempts);
                        base.evaluate();
                        Log.i(TAG, "Attempt #" + (i + 1) + " has succeeded!!");
                        return;
                    } catch (Throwable throwable) {
                        caughtThrowable = throwable;
                        Log.e(TAG, description.getMethodName() + ": Attempt " + (i + 1) +
                                " failed with " + throwable.getClass().getSimpleName(), throwable);
                    }
                }

                Log.e(TAG, "Test " + description.getMethodName() +
                        " - Giving up after " + numAttempts + " attempts as all attempts have failed :(");

                assert caughtThrowable != null;
                throw caughtThrowable;
            }
        };
    }
}
