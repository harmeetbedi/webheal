package org.webheal.scanner.attack;

import java.util.LinkedHashMap;
import java.util.Map;

public class BlindSqlAttack
{
    // map of ( AttackUri -> (param -> result_of_attack) ). Ensures that attack is only done once
    private Map<String,Map<String,AttackResult>> attacksDone = new LinkedHashMap<String,Map<String,AttackResult>>();
    
    public boolean isAttackAlreadyDone(String uri, String param) {
        uri = uri.toLowerCase().trim();
        param = param.toLowerCase().trim();
        Map<String,AttackResult> map = attacksDone.get(uri);
        return ( map != null ) ? map.containsKey(param) : false;
    }
    public void attack(String uri, String param) {
        if ( isAttackAlreadyDone(uri,param) ) {
            return;
        }
        /*
        String[] validandparam = { "x and 1=1--", "x' and '1'='1'--", "x\" and \"1\"=\"1\"--", "x and 1=1", "x' and '1'='1", "x\" and \"1\"=\"1" };
        String[] invalidandparam = { "x and 1=2--", "x' and '1'='2'--", "x\" and \"1\"=\"2\"--", "x and 1=2", "x' and '1'='2", "x\" and \"1\"=\"2" };
        String[] valid_validation = { "x and y and 1=1--", "x' and y and '1'='1'--", "x\" and y and \"1\"=\"1\"--", "x and y and 1=1", "x' and y and '1'='1", "x\" and y and \"1\"=\"1" };
        //NOT IN USE: string[] invalid_validation = { "x and y and 1=2--", "x' and y and '1'='2'--", "x\" and y and \"1\"=\"2\"--", "x and y and 1=2", "x' and y and '1'='2", "x\" and y and \"1\"=\"2" };
        String[] valid_calculations = { "2*4=8", "2+0+0+1=3", "4+2+2>4+1", "8*10=100-20" };
        String[] invalid_calculations = { "2*3=8", "2+4+0+1=3", "4+2+2<4+1", "8-10=100+20" };

        
        //double timediff = 0;
        public string masterid = "6";
        string Severity = "5";
        public static List<string> attacklist = new List<string>();
        URLValidation urlvalidate = new URLValidation();

        private boolean IsValid(string url, string inputname)
        {
            HtmlInfo htm = new HtmlInfo();
            bool flg = false;
            string tmpurl = url.Split('?')[0];
            //string tmpurl = htm.GetQueryString(url);
            if (!AppUtils.IsAttack(masterid))
            {
                return false;
            }
            Monitor.Enter(BlindSqlAttack.attacklist);
            if (BlindSqlAttack.attacklist.Contains(tmpurl + "_" + inputname))
            {
                flg = false;
            }
            else
            {
                BlindSqlAttack.attacklist.Add(tmpurl + "_" + inputname);
                flg = true;
            }
            Monitor.Exit(BlindSqlAttack.attacklist);
            return flg;
        }

        private static string StripTagsRegex(string source)
        {
            return Regex.Replace(source, "<.*?>", string.Empty);
        }

        private int GetSplitCount(string result)
        {
            return result.Split('<').Length;
        }

        public bool CompareHTML(string normal, string abnormal, string value, string vector)
        {
            vector = vector.Trim();
            normal = StripTagsRegex(normal).Replace("\t", "").Replace("\r", "").Replace("\n", "");
            abnormal = StripTagsRegex(abnormal).Replace(HttpUtility.UrlDecode(vector), value).Replace(HttpUtility.HtmlEncode(vector), value).Replace(vector, value).Replace(HttpUtility.HtmlEncode(HttpUtility.UrlDecode(vector)), value).Replace("\t", "").Replace("\r", "").Replace("\n", "");
            if(normal==abnormal)
            {
                return true;
            }
            return false;
        }


        public bool CheckBlindSqlInGet(string url, string inputname, string inputvalue, string errorvector, string[] blindvector)
        {
            try
            {
                HtmlInfo htm = new HtmlInfo();
                Attacker objAttack = new Attacker();
                bool flg = IsValid(url, inputname);
                
                return false;
                
                if (flg)
                {
                    AppUtils.Info("BlindSQLI:Entry:" + url);
                    string normal_result = "";
                    string error = "";
                    double normal_request_time = 0;
                    string[] validandparam = { "x and 1=1--", "x' and '1'='1'--", "x\" and \"1\"=\"1\"--", "x and 1=1", "x' and '1'='1", "x\" and \"1\"=\"1" };
                    string[] invalidandparam = { "x and 1=2--", "x' and '1'='2'--", "x\" and \"1\"=\"2\"--", "x and 1=2", "x' and '1'='2", "x\" and \"1\"=\"2" };
                    string[] valid_validation = { "x and y and 1=1--", "x' and y and '1'='1'--", "x\" and y and \"1\"=\"1\"--", "x and y and 1=1", "x' and y and '1'='1", "x\" and y and \"1\"=\"1" };
                    //NOT IN USE: string[] invalid_validation = { "x and y and 1=2--", "x' and y and '1'='2'--", "x\" and y and \"1\"=\"2\"--", "x and y and 1=2", "x' and y and '1'='2", "x\" and y and \"1\"=\"2" };
                    string[] valid_calculations = { "2*4=8", "2+0+0+1=3", "4+2+2>4+1", "8*10=100-20" };
                    string[] invalid_calculations = { "2*3=8", "2+4+0+1=3", "4+2+2<4+1", "8-10=100+20" };

                    var starttime = DateTime.Now.Ticks;
                    URLRequest normal_request = ExecuteRequest(url, ref normal_result, ref error, 500000);
                    TimeSpan timetaken = new TimeSpan(DateTime.Now.Ticks - starttime);

                    normal_request_time = timetaken.TotalSeconds;
                    
                    //////if (!normal_request.ResponseHeaders.ContentType.Contains("xml") && !normal_request.ResponseHeaders.ContentType.Contains("text") && !normal_request.ResponseHeaders.ContentType.Contains("json"))
                    //////{
                    //////    CheckQuickTimeBaseBlindSqlInjection(url, inputname, inputvalue, blindvector, normal_request_time);
                    //////    return false;
                    //////}
                    if (error.Contains("The operation has timed out"))
                    {
                        return false;
                    }

                    int normal_count = GetSplitCount(normal_result);

                    for (int i = 0; i <= validandparam.Length - 1; i++)
                    {
                        int v_andcount = 0, i_andcount = 0;
                        string v_andresult = "", i_andresult = "";
                        string v_andurl = objAttack.GenerateAttackData(url, inputname, validandparam[i].Replace("x", inputvalue));
                        string i_andurl = objAttack.GenerateAttackData(url, inputname, invalidandparam[i].Replace("x", inputvalue));
                        StringBuilder result_proof = new StringBuilder();

                        URLRequest v_andrequest = ExecuteRequest(v_andurl, ref v_andresult, ref error, 500000);
                        v_andcount = GetSplitCount(v_andresult);

                        URLRequest i_andrequest = ExecuteRequest(i_andurl, ref i_andresult, ref error, 500000);
                        i_andcount = GetSplitCount(i_andresult);

                        AppUtils.Debug("BlindSQLI:Calculation:" + v_andurl + " [ " + normal_count.ToString() + ", " + v_andcount.ToString() + ", " + i_andcount.ToString() + " ]");

                        if (CompareHTML(normal_result, v_andresult, inputvalue, validandparam[i].Replace("x", inputvalue)) && !CompareHTML(normal_result, i_andresult, inputvalue, invalidandparam[i].Replace("x", inputvalue)))
                        {
                            AppUtils.Debug("Blind SQL Injection Found: " + v_andurl + ", parameter: " + inputname);
                            string vector = valid_validation[i].Replace("x", inputvalue);
                            bool all_condition_pass = true;
                            foreach (string calc in invalid_calculations)
                            {
                                i_andurl = objAttack.GenerateAttackData(url, inputname, HttpUtility.UrlEncode(vector.Replace("y", calc)));
                                i_andrequest = ExecuteRequest(i_andurl, ref i_andresult, ref error, 500000);
                                if (CompareHTML(normal_result, i_andresult, inputvalue, vector.Replace("y", calc)))
                                {
                                    AppUtils.Debug("Blind SQL Injection REJECTED: " + url + ", parameter: " + inputname);
                                    all_condition_pass = false;
                                    break;
                                }
                                result_proof.Append(vector.Replace("y", calc) + " => <span style='color:red'><b>FALSE</b></span><br />");
                            }
                            if (!all_condition_pass)
                                continue;
                            foreach (string calc in valid_calculations)
                            {
                                v_andurl = objAttack.GenerateAttackData(url, inputname, HttpUtility.UrlEncode(vector.Replace("y", calc)));
                                v_andrequest = ExecuteRequest(v_andurl, ref v_andresult, ref error, 500000);
                                if (!CompareHTML(normal_result, v_andresult, inputvalue, vector.Replace("y", calc)))
                                {
                                    AppUtils.Debug("Blind SQL Injection REJECTED: " + url + ", parameter: " + inputname);
                                    all_condition_pass = false;
                                    break;
                                }
                                result_proof.Append(vector.Replace("y", calc) + " => <span style='color:green'><b>TRUE</b></span><br />");
                            }
                            if (!all_condition_pass)
                                continue;
                            string result = "Found blind SQL injection on " + url + ". The test cases executed: <br />" + result_proof;
                            AppUtils.Info(result);
                            string Title = "Blind SQL Injection";
                            ResultWriter.WriteAlertToResultXML(masterid, Severity, url, Title, result, invalidandparam[i].Replace("x", inputvalue), inputname, "", i_andurl, "", "get", i_andrequest.RequestURL, i_andrequest.RequestHeader, i_andrequest.ResponseHeader, "", "");
                            return true;
                        }
                    }
                    //CheckQuickTimeBaseBlindSqlInjection(url, inputname, inputvalue, blindvector, normal_request_time);
                }
            }
            catch (System.Exception ex)
            {
                AppUtils.Error(ex.ToString());
            }
            return false;
        }

        public void CheckQuickTimeBaseBlindSqlInjection(string url, string inputname, string inputvalue, string[] attackvector, double normal_request_time)
        {
            try
            {
                return;

                Attacker objAttack = new Attacker();
                AppUtils.Info("BlindSQLI:TimeEntry:" + url);
                if (normal_request_time == -1)
                {
                    
                    string normal_result = ""; string error = "";
                    var starttime = DateTime.Now.Ticks;
                    URLRequest normal_request = ExecuteRequest(url, ref normal_result, ref error, 500000);
                    TimeSpan timetaken = new TimeSpan(DateTime.Now.Ticks - starttime);
                    normal_request_time = timetaken.TotalSeconds;
                }

                for (int i = 0; i <= attackvector.Length - 1; i++)
                {
                    double[] req_time = new double[6];
                    string blindvector = "";
                    string result = "", attackurl = "";
                    string error = "";
                    URLRequest last_request = new URLRequest();

                    blindvector = attackvector[i].Replace("10", "15");
                    attackurl = objAttack.GenerateAttackData(url, inputname, blindvector);
                    var starttime = DateTime.Now.Ticks;
                    last_request = ExecuteRequest(attackurl, ref result, ref error, 500000);
                    TimeSpan timetaken = new TimeSpan(DateTime.Now.Ticks - starttime);

                    if (normal_request_time >= timetaken.TotalSeconds || timetaken.TotalSeconds < 15)
                        continue;

                    for (int cnt = 1; cnt <= 5; cnt++)
                    {
                        if(i==0)
                            blindvector = attackvector[i].Replace("10", (cnt * 3).ToString());
                        else
                            blindvector = inputvalue + attackvector[i].Replace("10", (cnt * 3).ToString());
                        attackurl = objAttack.GenerateAttackData(url, inputname, blindvector);

                        starttime = DateTime.Now.Ticks;
                        last_request = ExecuteRequest(attackurl, ref result, ref error, 500000);
                        timetaken = new TimeSpan(DateTime.Now.Ticks - starttime);
                        AppUtils.Debug("\t:" + attackurl + " " + (cnt*3).ToString() + " [ " + (timetaken.TotalSeconds).ToString() + " ]");
                        if (error.Contains("The operation has timed out"))
                        {
                            return;
                        }

                        req_time[cnt] = timetaken.TotalSeconds;
                    }
                    AppUtils.Debug("Blind:TimeCalc: " + url + " >> \n[3 Seconds => " + req_time[1].ToString() + "]\n[6 Seconds => " + req_time[2].ToString() + "]\n[9 Seconds => " + req_time[3].ToString() + "]\n[12 Seconds => " + req_time[4].ToString() + "]\n[15 Seconds => " + req_time[5].ToString() + "]\n");

                    if (req_time[1] >= 3 && req_time[2] >= 6 && req_time[3] >= 9 && req_time[4] >= 12 && req_time[5] >=15 && req_time[5] - normal_request_time >= req_time[1])
                    {
                        //if (req_time[1] - normal_request_time >= 3 && req_time[2] - normal_request_time >= 6 && req_time[3] - normal_request_time >= 9 && req_time[4] - normal_request_time >= 12 && req_time[5] - normal_request_time >= 15)
                        //{
                        result = "Found blind SQL injection on " + url + ". Request execution matrix: <br />[3 Seconds => " + req_time[1].ToString() + "]<br />[6 Seconds => " + req_time[2].ToString() + "]<br />[9 Seconds => " + req_time[3].ToString() + "]<br />[12 Seconds => " + req_time[4].ToString() + "]<br />[15 Seconds => " + req_time[5].ToString() + "]<br />";
                            string Title = "Blind SQL Injection";
                            ResultWriter.WriteAlertToResultXML(masterid, Severity, url, Title, result, blindvector, inputname, "", attackurl, "", "get", last_request.ResponseURL, last_request.RequestHeader, last_request.ResponseHeader, "", "");
                            return;
                        //}

                    }
                    else if (req_time[1] >= 3 && req_time[2] >= 6 && req_time[3] >= 9 && req_time[4] >= 12 && req_time[5] >= 15 && req_time[5] < req_time[1])
                    {
                        result = "Found <b>possible</b> blind SQL injection on " + url + ". Request execution matrix: <br />[3 Seconds => " + req_time[1].ToString() + "]<br />[6 Seconds => " + req_time[2].ToString() + "]<br />[9 Seconds => " + req_time[3].ToString() + "]<br />[12 Seconds => " + req_time[4].ToString() + "]<br />[15 Seconds => " + req_time[5].ToString() + "]<br />";
                        string Title = "Blind SQL Injection";
                        ResultWriter.WriteAlertToResultXML(masterid, Severity, url, Title, result, blindvector, inputname, "", attackurl, "", "get", last_request.ResponseURL, last_request.RequestHeader, last_request.ResponseHeader, "", "");
                        return;
                    }


                }

            }
            catch (System.Exception ex)
            {
                AppUtils.Error(ex.ToString());
            }
        }

        
        private URLRequest ExecuteRequest(string url, ref string result, ref string httperror, int timeout = 0)
        {
            URLRequest myrequest = null;
            try
            {
                myrequest = new URLRequest(url, "get", "");
                if (timeout != 0)
                {
                    myrequest.TimeOut = timeout;
                }
                myrequest.AllowReditect = false;
                result = myrequest.Execute();
            }
            catch (System.Exception ex)
            {
                AppUtils.Error(ex.ToString());
            }
            return myrequest;
        }

           /// <summary>
        /// This function does attack on page based on input fields available on this page.
        /// This function set attack string in value of input fields one by one and submit the form to find inputxss.
        /// </summary>
        /// <param name="objpage"> (PageData objpage) --> It is an object with url and  listof forms and its property and list of inputs on forms</param>
        /*public void CheckBlindSqlInPost(ref PageData objpage,ref List<HtmlItem> HtmlItems,ref List<HtmlItem> submitlist, string inputname, int inputindex, int formindex, string[] blindvector)
        {
            try
            {
                Vulnerabilitie va = new Vulnerabilitie();
                Parser objparser = new Parser();
                ResultMatch objmatch = new ResultMatch();
                HtmlInfo htm = new HtmlInfo();
                string blindattackvector = blindvector[0];
                string action = "", result = "";
                action = new Uri(new Uri(objpage.Url), objpage.PageForms[formindex].Action).AbsoluteUri;

                for (int si = 0; si <= submitlist.Count - 1; si++)
                {
                    if (htm.IsInputUrlEncodeUnicode(objpage.PageForms[formindex].HtmlItems[inputindex]) || htm.IsInputTypeSubmit(objpage.PageForms[formindex].HtmlItems[inputindex]) || urlvalidate.IsExcludeurl(submitlist[si].Name))
                    {
                        continue;
                    }
                    Attacker atkdata = new Attacker();
                    atkdata.GenerateAttackData(objpage.PageForms[formindex].HtmlItems, submitlist[si], objpage.PageForms[formindex].HtmlItems[inputindex].Name, blindattackvector);
                    /*if (atkdata.AttackData != "")
                    {
                        URLRequest myrequest = new URLRequest();
                        myrequest.RequestURL = action;
                        myrequest.RequestMethod = objpage.PageForms[formindex].Method;
                        myrequest.PostData = atkdata.AttackData;
                        if (atkdata.AttackData.Length > 1000)
                        {
                            myrequest.PostDataLimit = atkdata.LimitAttackData;
                        }
                        if (myrequest.RequestMethod.ToLower().Trim() == "get")
                        {
                            if (myrequest.RequestURL.Contains("?"))
                            {
                                myrequest.RequestURL = myrequest.RequestURL + "&" + atkdata.AttackData;
                            }
                            else
                            {
                                myrequest.RequestURL = myrequest.RequestURL + "?" + atkdata.AttackData;
                            }
                        }
                        result = myrequest.Execute();
                        if (result != "")
                        {
                            //CheckOtherVA(action, result, "", myrequest.RequestMethod, objpage.PageForms[i].htmlitems[ci].name, AttackStrings[ji], myrequest.StatusCode, myrequest.RequestHeader);
                            if (myrequest.RequestMethod.ToLower().Trim() == "get")
                            {
                                va.CheckOtherVulnerabilities(action, result, myrequest.RequestURL, "get", objpage.PageForms[formindex].HtmlItems[inputindex].Name, blindattackvector, myrequest.RequestHeader, myrequest.ResponseHeader, myrequest.StatusCode.ToString());
                            }
                            else
                            {
                                va.CheckOtherVulnerabilities(action, result, "", "post", objpage.PageForms[formindex].HtmlItems[inputindex].Name, blindattackvector, myrequest.RequestHeader, myrequest.ResponseHeader, myrequest.StatusCode.ToString());
                            }
                            string attackresult = objmatch.MatchAttckString(result, AttackStrings[ji], MatchStrings, ref regex, ref foundstring);
                            //////if (resurl != action)
                            //////{
                            //////    //Parse for forms and enque
                            //////}
                            if (attackresult != "")
                            {
                                string inj_url = "";
                                if (myrequest.RequestMethod.ToLower().Trim() == "get")
                                {
                                    inj_url = myrequest.RequestURL;
                                }
                                flgvulfounnd = true;
                                ResultWriter.WriteAlertToResultXML(masterid, Severity, action, Title, attackresult, AttackStrings[ji], objpage.PageForms[i].HtmlItems[ci].Name, "", inj_url, objpage.Url, myrequest.RequestMethod, myrequest.ResponseURL, myrequest.RequestHeader, myrequest.ResponseHeader, regex, foundstring);
                                break;
                            }
                        }
                    }
                }
            }
            catch (System.Exception ex)
            {
                AppUtils.Error(ex.ToString());
            }
        }*/
    
    }
}

