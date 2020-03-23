//  Copyright (c) Microsoft Corporation.
//  All rights reserved.
//
//  This code is licensed under the MIT License.
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files(the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions :
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.
package com.microsoft.identity.common;

import android.content.Context;

import androidx.test.InstrumentationRegistry;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.microsoft.identity.common.internal.util.ClockSkewManager;
import com.microsoft.identity.common.internal.util.IClockSkewManager;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Date;

import static org.junit.Assert.assertEquals;

@RunWith(AndroidJUnit4.class)
public class ClockSkewManagerTest {

    private Context sContext;
    private static IClockSkewManager sClockSkewMgr;

    @Before
    public void setUp() {
        sContext = InstrumentationRegistry.getTargetContext();
    }

    @After
    public void tearDown() {
        // Reset the skew to 0
        if (null != sClockSkewMgr) {
            sClockSkewMgr.onTimestampReceived(0L);
        }

        // Reset the Context
        sContext = null;
    }

    @Test
    public void testOnTimestampReceived() {
        sClockSkewMgr = new ClockSkewManager(sContext) {
            @Override
            public Date getCurrentClientTime() {
                return new Date(12345);
            }
        };

        final Date serverTime = new Date(67890);
        sClockSkewMgr.onTimestampReceived(serverTime.getTime());
        assertEquals(-55545, sClockSkewMgr.getSkewMillis());
    }

    @Test
    public void testOnTimestampReceived2() {
        sClockSkewMgr = new ClockSkewManager(sContext) {
            @Override
            public Date getCurrentClientTime() {
                return new Date(67890);
            }
        };

        final Date serverTime = new Date(12345);
        sClockSkewMgr.onTimestampReceived(serverTime.getTime());
        assertEquals(55545, sClockSkewMgr.getSkewMillis());
    }

    @Test
    public void testGetReferenceTime() {
        sClockSkewMgr = new ClockSkewManager(sContext) {
            @Override
            public Date getCurrentClientTime() {
                return new Date(67890);
            }

            @Override
            public long getSkewMillis() {
                return 42L;
            }
        };

        assertEquals(67848L, sClockSkewMgr.getAdjustedReferenceTime().getTime());
    }

    @Test
    public void testToClientTime() {
        sClockSkewMgr = new ClockSkewManager(sContext) {
            @Override
            public long getSkewMillis() {
                return 42L;
            }
        };

        assertEquals(67932L, sClockSkewMgr.toClientTime(67890).getTime());
    }

    @Test
    public void testToReferenceTime() {
        sClockSkewMgr = new ClockSkewManager(sContext) {
            @Override
            public long getSkewMillis() {
                return 42L;
            }
        };

        assertEquals(67848L, sClockSkewMgr.toReferenceTime(67890).getTime());
    }
}
