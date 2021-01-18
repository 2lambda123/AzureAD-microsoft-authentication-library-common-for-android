﻿//  Copyright (c) Microsoft Corporation.
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

using System;
using System.Collections.Generic;
//using PerfClTool.DbClasses;
using System.Linq;

namespace PerfClTool.Measurement
{
    internal class MeasurementsStore
    {
        public static Dictionary<string, List<PerfMeasurementsSet>> AllScenarioMeasurements { get; private set; }
        static MeasurementsStore()
        {
            AllScenarioMeasurements = new Dictionary<string, List<PerfMeasurementsSet>>();
        }

        public static void clear()
        {
            AllScenarioMeasurements = new Dictionary<string, List<PerfMeasurementsSet>>();
        }

        public static void AddScenarioIterationMeasurements(String scenarioName, PerfData perfData, List<PerfMeasurementConfiguration> enabledMeasurementsConfiguration)
        {
            if (!AllScenarioMeasurements.ContainsKey(scenarioName))
            {
                AllScenarioMeasurements.Add(scenarioName, new List<PerfMeasurementsSet>());
                foreach (var measurementConfiguration in enabledMeasurementsConfiguration)
                {
                    AllScenarioMeasurements[scenarioName].Add(new PerfMeasurementsSet(measurementConfiguration));
                }
            }
            foreach (var measurementSet in AllScenarioMeasurements[scenarioName])
            {
                measurementSet.AddIterationMeasurement(perfData);
            }
        }

        public static void GenerateAggregateMeasurements()
        {
            foreach (var measurementSetList in AllScenarioMeasurements.Values)
            {
                //Delete any measurementSet that has no actual data.
                measurementSetList.RemoveAll(x => x._iterationMeasurements.Count == 0);
                measurementSetList.ForEach(t => t.GenerateAggregateMeasurements());
            }
        }

        public static void DumpResponseTimeSummaryToFile(String fileName)
        {
            PerfMeasurementsSet.AppendMeasurementSummaryHeadersToFile(fileName);
            foreach (var scenarioMeasurements in AllScenarioMeasurements)
            {
                AllScenarioMeasurements[scenarioMeasurements.Key].ForEach(t => t.AppendMeasurementSummaryToFile(fileName, scenarioMeasurements.Key, PerformanceMetricType.ResponseTime));
            }
        }

        public static void DumpRssEndSummaryToFile(String fileName)
        {
            PerfMeasurementsSet.AppendMeasurementSummaryHeadersToFile(fileName);
            foreach (var scenarioMeasurements in AllScenarioMeasurements)
            {
                AllScenarioMeasurements[scenarioMeasurements.Key].ForEach(t => t.AppendMeasurementSummaryToFile(fileName, scenarioMeasurements.Key, PerformanceMetricType.RssEnd));
            }
        }
        public static void DumpVssEndSummaryToFile(String fileName)
        {
            PerfMeasurementsSet.AppendMeasurementSummaryHeadersToFile(fileName);
            foreach (var scenarioMeasurements in AllScenarioMeasurements)
            {
                AllScenarioMeasurements[scenarioMeasurements.Key].ForEach(t => t.AppendMeasurementSummaryToFile(fileName, scenarioMeasurements.Key, PerformanceMetricType.VssEnd));
            }
        }

        public static void DumpAllMeasurementsDataToFile(String fileName)
        {
            foreach (var scenarioMeasurements in AllScenarioMeasurements)
            {
                AllScenarioMeasurements[scenarioMeasurements.Key].ForEach(t => t.AppendMeasurementsDataToFile(fileName, scenarioMeasurements.Key));
            }
        }
        /*public static void InsertMeasurementsInDb(String taskId)
        {
            if(taskId == null)
            {
                //Standalone PerfCLTool run case. No need to insert into db
                //PerfConsole.LogDebugMessage("Not inserting results into db");
                return;
            }
            using (var dataContext = new DataClassesDataContext())
            {
                foreach (var scenarioMeasurements in AllScenarioMeasurements)
                {
                    
                    string scenarioName = scenarioMeasurements.Key;
                    var scenarioId = (from s in dataContext.PerfScenarioDetails where s.ScenarioName.Equals(scenarioName) select s.Id).First();
                    foreach (var measurement in AllScenarioMeasurements[scenarioMeasurements.Key])
                    {
                        PerfTaskResult result = new PerfTaskResult()
                        {
                            Average = measurement._average.ResponseTime.MeasurementValue,
                            Best75Avg = measurement._best75Avg.ResponseTime.MeasurementValue,
                            Best75RssAvg = measurement._best75Avg.RssEnd.MeasurementValue,
                            Best75RssStdev = measurement._best75Stdev.RssEnd.MeasurementValue,
                            Best75Stdev = measurement._best75Stdev.ResponseTime.MeasurementValue,
                            Best75VssAvg = measurement._best75Avg.VssEnd.MeasurementValue,
                            Best75VssStdev = measurement._best75Stdev.VssEnd.MeasurementValue,
                            Max = measurement._max.ResponseTime.MeasurementValue,
                            Min = measurement._min.ResponseTime.MeasurementValue,
                            MeasurementId = measurement._measurementConfiguration.Id,
                            NumIterations = Convert.ToInt32(measurement._numIterations.ResponseTime.MeasurementValue),
                            Stdev = measurement._stdev.ResponseTime.MeasurementValue,
                            TaskId = Convert.ToDecimal(taskId),
                            _25Percentile = measurement._percentile25.ResponseTime.MeasurementValue,
                            _50Percentile = measurement._percentile50.ResponseTime.MeasurementValue,
                            _75Percentile = measurement._percentile75.ResponseTime.MeasurementValue,
                            ScenarioId = scenarioId,
                            MinRss = measurement._min.RssEnd.MeasurementValue,
                            MaxRss = measurement._max.RssEnd.MeasurementValue,
                            MinVss = measurement._min.VssEnd.MeasurementValue,
                            MaxVss = measurement._max.VssEnd.MeasurementValue
                        };
                        dataContext.PerfTaskResults.InsertOnSubmit(result);           
                    }
                }
                dataContext.SubmitChanges();
            }
        }*/
    }
}
