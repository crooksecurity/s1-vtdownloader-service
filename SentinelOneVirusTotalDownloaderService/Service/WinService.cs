using Common.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using Topshelf;
using System.Timers;
using System.IO;
using System.Text.RegularExpressions;
using RestSharp;
using RestSharp.Authenticators;
using System.Diagnostics;
using System.Net;
using WinSCP;
using System.Threading;
using System.Security.Cryptography;

namespace SentinelOneVirusTotalDownloaderService.Service
{
    class S1VTDownloader
    {
        private System.Timers.Timer workTimer = null;

        private IniFile MyIni = new IniFile("settings.ini");
        private string workingDirectory = "";

        private string VTKey = "";
        private string VTQuery = "";
        private string VTQueryMac = "";
        private string VTCompetitors = "";
        private int VTNumberOfMalwares = 50;
        private string BaseURL = "https://www.virustotal.com";

        private string S1Server = "";
        private string S1ServerToken = "";
        private string S1AgentVersion = "";

        private string ftpUrl = "";
        private string ftpUsername = "";
        private string ftpPassword = "";
        private string sshFingerPrint = "";
        private string remoterootdir = "";

        private int win_start = 0;
        private int win_end = 1;
        private int mac_start = 2;
        private int mac_end = 3;
        private string mac_directory = "";

        private int detection_wait_time = 5000;

        private string readme = "";

        public ILog Log { get; private set; }

        public S1VTDownloader(ILog logger)
        {
            // IocModule.cs needs to be updated in case new paramteres are added to this constructor
            if (logger == null)
                throw new ArgumentNullException(nameof(logger));
            Log = logger;
        }

        public bool Start(HostControl hostControl)
        {
            try
            {
                Log.Info($"Start command received.");

                workingDirectory = Directory.GetCurrentDirectory();
                MyIni.TheFile = workingDirectory + "\\settings.ini";

                Log.Info("Working directory: " + workingDirectory);

                workTimer = new System.Timers.Timer();
                workTimer.Interval = 3600000;  // 3,600 seconds is one hour
                // workTimer.Interval = 120000;  // 3,600 seconds is one hour
                workTimer.Elapsed += new System.Timers.ElapsedEventHandler(workTimer_Tick);
                workTimer.Enabled = true;
                workTimer_Tick(this, null);

                return true;
            }
            catch (Exception ex)
            {
                workTimer.Enabled = false;
                Log.Error($"Error starting service: " + ex.Message);
                return false;
            }
        }

        public bool Stop(HostControl hostControl)
        {
            Log.Trace($"Stop command received.");
            workTimer.Enabled = false;
            return true;
        }

        public bool Pause(HostControl hostControl)
        {
            Log.Trace($"Pause command received.");
            workTimer.Enabled = false;
            //TODO: Implement your service start routine.
            return true;
        }

        public bool Continue(HostControl hostControl)
        {
            Log.Trace($"Continue command received.");
            workTimer.Enabled = true;
            return true;
        }

        public bool Shutdown(HostControl hostControl)
        {
            Log.Trace($"Shutdown command received.");
            //TODO: Implement your service stop routine.
            return true;
        }

        private void workTimer_Tick(object sender, ElapsedEventArgs e)
        {
            try
            {
                Directory.SetCurrentDirectory(workingDirectory);

                MyIni.TheFile = workingDirectory + "\\settings.ini";

                VTKey = MyIni.GetValue("VT", "apikey");
                VTQuery = MyIni.GetValue("VT", "win_query");
                VTQueryMac = MyIni.GetValue("VT", "mac_query");
                VTCompetitors = MyIni.GetValue("VT", "competitors");

                S1Server = MyIni.GetValue("S1", "url");
                S1ServerToken = MyIni.GetValue("S1", "token");

                ftpUrl = MyIni.GetValue("FTP", "url");
                ftpUsername = MyIni.GetValue("FTP", "username");
                ftpPassword = MyIni.GetValue("FTP", "password");
                sshFingerPrint = MyIni.GetValue("FTP", "sshfingerprint");
                remoterootdir = MyIni.GetValue("FTP", "remoterootdir");

                win_start = MyIni.GetInteger("VT", "win_start");
                win_end = MyIni.GetInteger("VT", "win_end");
                mac_start = MyIni.GetInteger("VT", "mac_start");
                mac_end = MyIni.GetInteger("VT", "mac_end");

                mac_directory = MyIni.GetValue("S1", "mac_directory");
                detection_wait_time = MyIni.GetInteger("S1", "detection_wait_time");

                /*
                TimeSpan start_win = new TimeSpan(win_start, 0, 0);
                TimeSpan end_win = new TimeSpan(win_end, 0, 0);

                TimeSpan start_mac = new TimeSpan(mac_start, 0, 0);
                TimeSpan end_mac = new TimeSpan(mac_end, 0, 0);
                */

                TimeSpan now = DateTime.UtcNow.TimeOfDay;
                int nowHour = now.Hours;

                if ((nowHour >= win_start) && (nowHour < win_end))
                {
                    S1AgentVersion = MyIni.GetValue("S1", "win_agent_version");
                    VTNumberOfMalwares = MyIni.GetInteger("VT", "numberofmalwares_win");
                    Log.Trace("Ready for Windows run");
                    DownloadFromVT("windows");
                    // ChangeSha1(fileName: ".\\2017-12-13\\windows\\v2.0.0.6077\\1f840aac99955e51ef6def92f5b8c3e2a279fca3");

                    /*  Testing and bypassing VT
                    DateTime thisDay = DateTime.Today;
                    string today = thisDay.ToString("yyyy-MM-dd");
                    string folderToday = ".\\" + today + "\\";
                    string folderOS = ".\\" + today + "\\" + "windows" + "\\";
                    S1DetectionCheckSingle(folderOS, "064a87b4a9c5233bf52f4ba6942063257a95c27c");
                    */
                }
                else if ((nowHour >= mac_start) && (nowHour < mac_end))
                {
                    S1AgentVersion = MyIni.GetValue("S1", "mac_agent_version");
                    VTNumberOfMalwares = MyIni.GetInteger("VT", "numberofmalwares_mac");
                    DownloadFromVT("macos");
                    Log.Trace("Ready for macOS run");
                }
                else
                {
                    // Log.Trace("Waiting for the daily appointed time to run...");
                    Log.Trace("Waiting=> Now: " + now.Hours.ToString() + "; win: " + win_start.ToString() + ", " + win_end.ToString() + "; mac: " + mac_start.ToString() + ", " + mac_end.ToString());
                    return;
                }

            }
            catch (Exception ex)
            {
                Log.Error($"Error in Work Timer: " + ex.Message);
            }
        }

        private void DownloadFromVT(string winOrmac)
        {
            try
            {
                string[] competitors = VTCompetitors.Split(',');
                competitors = competitors.Concat(new string[] { "lastround" }).ToArray();
                int numOfCompetitors = competitors.Length;

                if (winOrmac == "macos")
                {
                    numOfCompetitors = 2;
                }

                int itemsPerCompetitor = VTNumberOfMalwares / (numOfCompetitors - 1);
                int fileCounter = 0;
                int remainderItems = 0;
                int totalFileDownloaded = 0;

                Log.Trace("Number of Competitors: " + (numOfCompetitors - 1));
                Log.Trace("Items per Competitor: " + itemsPerCompetitor);

                string currentDir = Directory.GetCurrentDirectory();
                string workingDir = Directory.GetCurrentDirectory();

                if (winOrmac == "macos")
                {
                    // workingDir = "z:\\Downloads";
                    workingDir = mac_directory;
                }
                else
                {
                    workingDir = ".";
                }

                DateTime thisDay = DateTime.UtcNow;
                string today = thisDay.ToString("yyyy-MM-dd");
                string folderToday = workingDir + "\\" + today + "\\";
                string folderOS = workingDir + "\\" + today + "\\" + winOrmac + "\\";
                string folderVersion = workingDir + "\\" + today + "\\" + winOrmac + "\\" + S1AgentVersion + "\\";
                string folderVersionChanged = workingDir + "\\" + today + "\\" + winOrmac + "\\" + S1AgentVersion + "-hash-changed\\";

                string rowTemplate = "<tr><td>$filename$</td><td>$sha1$</td><td>$scandate$</td><td>$fileiden$</td><td>$fileos$</td><td>$filetype$</td><td>$fileext$</td><td><a target=\"vt\" href=\"$vtlink$\">$vtlink$</a></td></tr>\r\n";

                FileInfo file = new FileInfo(folderToday);
                file.Directory.Create(); // If the directory already exists, this method does nothing.
                FileInfo file2 = new FileInfo(folderOS);
                file2.Directory.Create(); // If the directory already exists, this method does nothing.
                FileInfo file3 = new FileInfo(folderVersion);
                file3.Directory.Create(); // If the directory already exists, this method does nothing.

                DirectoryInfo di = new DirectoryInfo(folderVersion);
                foreach (FileInfo fileToDelete in di.GetFiles())
                    fileToDelete.Delete();
                foreach (DirectoryInfo dirToDelete in di.GetDirectories())
                    dirToDelete.Delete(true);

                if (winOrmac == "windows")
                {
                    FileInfo file4 = new FileInfo(folderVersionChanged);
                    file4.Directory.Create(); // If the directory already exists, this method does nothing.

                    DirectoryInfo di2 = new DirectoryInfo(folderVersionChanged);
                    foreach (FileInfo fileToDelete in di2.GetFiles())
                        fileToDelete.Delete();
                    foreach (DirectoryInfo dirToDelete in di2.GetDirectories())
                        dirToDelete.Delete(true);
                }

                string templateFile = File.ReadAllText(currentDir + "\\included_files.html");
                templateFile = templateFile.Replace("$date$", today);
                string os = "Windows";
                if (winOrmac == "macos") os = "macOS";
                templateFile = templateFile.Replace("$version$", os + " - " + S1AgentVersion);

                // readme = today + "-" + winOrmac + "-readme-" + S1AgentVersion + ".html";
                readme = "readme.html";

                File.WriteAllText(folderVersion + readme, templateFile);

                #region VT Query

                for (int j = 0; j < numOfCompetitors; j++)
                {
                    totalFileDownloaded = Directory.GetFiles(folderVersion).Length - 1;

                    if (totalFileDownloaded >= VTNumberOfMalwares ||
                        totalFileDownloaded >= ((j + 1) * itemsPerCompetitor))
                    {
                        break;
                    }

                    string resourceString = "";

                    if (winOrmac == "windows")
                        resourceString =  "vtapi/v2/file/search?" + "apikey=" + VTKey + "&query=" + VTQuery + " " + competitors[j].ToLower() + ":clean";
                        // resourceString = "vtapi/v2/file/search?" + "apikey=" + VTKey + "&query=" + VTQuery;
                    else
                        resourceString = "vtapi/v2/file/search?" + "apikey=" + VTKey + "&query=" + VTQueryMac;

                    if (competitors[j].ToLower() == "lastround")
                    {
                        int fileCount = Directory.GetFiles(folderVersion).Length;
                        remainderItems = VTNumberOfMalwares - fileCount;
                        if (remainderItems == 0)
                            break;
                        if (winOrmac == "windows")
                            resourceString = "vtapi/v2/file/search?" + "apikey=" + VTKey + "&query=" + VTQuery;
                        else
                            resourceString = "vtapi/v2/file/search?" + "apikey=" + VTKey + "&query=" + VTQueryMac;
                    }

                    var restClient = new RestClient();
                    restClient.BaseUrl = new Uri(BaseURL);

                    var request = new RestRequest();
                    request.Resource = resourceString;
                    Log.Trace("VT Query: " + request.Resource);
                    int rowCount = 0;

                    IRestResponse response = restClient.Execute(request);
                    dynamic x = Newtonsoft.Json.JsonConvert.DeserializeObject(response.Content);

                    if (x == null)
                    {
                        Log.Trace("VT API error: No content or response");
                        return;
                    }

                    if (x == null || x.response_code == -1)
                    {
                        Log.Trace("VT API error: " + x.verbose_msg);
                        return;
                    }

                    Log.Trace("VT message: " + x.verbose_msg);

                    /*
                    dynamic x = Newtonsoft.Json.JsonConvert.DeserializeObject(File.ReadAllText("MacQueryFromVT.out"));
                    File.WriteAllText("MacQueryFromVT.out", x.ToString());
                    */

                    rowCount = (int)x.hashes.Count;

                    string scandate = "";
                    string filename = "";
                    string fileiden = "";
                    string fileos = "";
                    string filetype = "";
                    string fileext = "";
                    string vtlink = "";
                    string fileanalysis = "";
                    string sha1 = "";

                    int CurrentFileCount = 0;

                    if (rowCount > 0)
                    {
                        bool originalFileDetected = false;
                        bool changedFileDetected = false;

                        for (int i = 0; i < rowCount; i++)
                        {
                            originalFileDetected = false;
                            changedFileDetected = false;

                            string includedFiles = File.ReadAllText(folderVersion + readme);
                            string rowsOfIncludedFiles = "";
                            fileCounter++;

                            fileanalysis = VTFileReport(x.hashes[i].ToString());
                            dynamic y = Newtonsoft.Json.JsonConvert.DeserializeObject(fileanalysis);

                            scandate = (y.scan_date == null) ? "null" : y.scan_date;

                            if (winOrmac == "windows")
                            {
                                filename = (y.additional_info == null ||
                                            y.additional_info.exiftool == null ||
                                            y.additional_info.exiftool.OriginalFileName == null) ? "null" : y.additional_info.exiftool.OriginalFileName;

                                fileiden = (y.additional_info == null ||
                                            y.additional_info.magic == null) ? "null" : y.additional_info.magic;

                                fileos = (y.additional_info == null ||
                                            y.additional_info.exiftool == null ||
                                            y.additional_info.exiftool.FileOS == null) ? "null" : y.additional_info.exiftool.FileOS;

                                filetype = (y.additional_info == null ||
                                            y.additional_info.exiftool == null ||
                                            y.additional_info.exiftool.FileType == null) ? "null" : y.additional_info.exiftool.FileType;

                                fileext = (y.additional_info == null ||
                                            y.additional_info.exiftool == null ||
                                            y.additional_info.exiftool.FileTypeExtension == null) ? "null" : y.additional_info.exiftool.FileTypeExtension;
                            }
                            else
                            {
                                filename = (y.submission_names == null ||
                                            y.submission_names.Count == 0) ? "null" : y.submission_names[0];

                                fileiden = (y.additional_info == null ||
                                            y.additional_info.trid == null) ? "null" : y.additional_info.trid;

                                // fileos = (y.additional_info == null ||
                                //            y.additional_info["behavior-v1"] == null ||
                                //            y.additional_info["behavior-v1"].version == null) ? "null" : y.additional_info["behavior-v1"].version;

                                fileos = "macOS";

                                filetype = (y.type == null ||
                                            y.type == null) ? "null" : y.type;

                                fileext = "null";
                            }

                            vtlink = (y.permalink == null) ? "null" : y.permalink;

                            sha1 = (y.sha1 == null) ? "null" : y.sha1;

                            string str = filename;
                            bool isLetterorDigit = !string.IsNullOrEmpty(str) && char.IsLetterOrDigit(str[0]);

                            // if (filename != "null" && filename.StartsWith(".") == false)
                            if (filename != "null" && isLetterorDigit)
                            {
                                // using (var writer = File.OpenWrite(file + "\\" + filename))
                                using (var writer = File.OpenWrite(file3 + "\\" + sha1))
                                {
                                    var client = new RestClient(BaseURL);
                                    var requestDownload = new RestRequest("vtapi/v2/file/download?query=&" + "apikey=" + VTKey + "&hash=" + x.hashes[i].ToString());
                                    requestDownload.ResponseWriter = (responseStream) => responseStream.CopyTo(writer);
                                    var responseDownload = client.DownloadData(requestDownload);
                                }

                                // long filesize = new System.IO.FileInfo(file + "\\" + filename).Length;
                                long filesize = new System.IO.FileInfo(file3 + "\\" + sha1).Length;
                                // Log.Trace("File name: " + filename + ", Size: " + filesize.ToString());
                                Log.Trace("File name: " + sha1 + ", Size: " + filesize.ToString());

                                if (includedFiles.Contains(sha1) == false)
                                {
                                    rowsOfIncludedFiles = rowTemplate.Replace("$filename$", filename)
                                        .Replace("$filename$", filename.Replace("\r\n", "<br/>").Replace("\n","<br/>"))
                                        .Replace("$sha1$", sha1.Replace("\r\n", "<br/>").Replace("\n", "<br/>"))
                                        .Replace("$scandate$", scandate.Replace("\r\n", "<br/>").Replace("\n", "<br/>"))
                                        .Replace("$fileiden$", fileiden.Replace("\r\n", "<br/>").Replace("\n", "<br/>"))
                                        .Replace("$fileos$", fileos.Replace("\r\n", "<br/>").Replace("\n", "<br/>"))
                                        .Replace("$filetype$", filetype.Replace("\r\n", "<br/>").Replace("\n", "<br/>"))
                                        .Replace("$fileext$", fileext.Replace("\r\n", "<br/>").Replace("\n", "<br/>"))
                                        .Replace("$vtlink$", vtlink.Replace("\r\n", "<br/>").Replace("\n", "<br/>"));

                                    rowsOfIncludedFiles = rowsOfIncludedFiles + "\r\n<!-- $data$ -->";
                                    includedFiles = includedFiles.Replace("<!-- $data$ -->", rowsOfIncludedFiles);
                                    File.WriteAllText(folderVersion + readme, includedFiles);

                                    if (winOrmac == "windows")
                                        File.WriteAllText(folderVersionChanged + readme, includedFiles);
                                }

                                if (winOrmac == "windows")
                                {
                                    string newSha1 = ChangeSha1(folderVersion, folderVersionChanged, sha1);
                                    originalFileDetected = S1DetectionCheckSingle(folderVersion, sha1, sha1);
                                    changedFileDetected = S1DetectionCheckSingle(folderVersionChanged, sha1, newSha1);
                                }
                                else
                                {
                                    originalFileDetected = S1DetectionCheckSingle(folderVersion, sha1, sha1);
                                    changedFileDetected = true;
                                }

                                if (originalFileDetected && changedFileDetected)
                                {
                                    CurrentFileCount++;
                                }
                            }

                            // minus one because there is a readme.html file that is not the malware file
                            totalFileDownloaded = Directory.GetFiles(folderVersion).Length - 1;

                            if (totalFileDownloaded >= VTNumberOfMalwares ||
                                totalFileDownloaded >= ((j + 1) * itemsPerCompetitor))
                            {
                                break;
                            }
                        }
                    }
                }


                #endregion

                // S1DetectionCheck(folderOS);
                string zfile = ZipFolder(winOrmac, workingDir, S1AgentVersion);
                FTPUpload(today, winOrmac, zfile);
                FTPUpload(today, winOrmac, folderVersion + readme);

                if (winOrmac == "windows")
                {
                    string zfileChanged = ZipFolder(winOrmac, workingDir, S1AgentVersion + "-hash-changed");
                    FTPUpload(today, winOrmac, zfileChanged);
                    FTPUpload(today, winOrmac, folderVersionChanged + readme);
                }

                ResolveThreats();
            }
            catch (Exception ex)
            {
                Log.Error($"Error in DownloadFromVT() method: " + ex.Message);
            }
        }

        public string GetSubstringByString(string a, string b, string c)
        {
            return c.Substring((c.IndexOf(a) + a.Length), (c.IndexOf(b) - c.IndexOf(a) - a.Length));
        }

        private void FTPUpload(string remoteDirectory, string winOrmac, string uploadFile)
        {
            /*
            var MyIni = new IniFile("settings.ini");
            string ftpUrl = MyIni.GetValue("FTP", "url");
            string ftpUsername = MyIni.GetValue("FTP", "username");
            string ftpPassword = MyIni.GetValue("FTP", "password");
            string sshFingerPrint = MyIni.GetValue("FTP", "sshfingerprint");
            string remoterootdir = MyIni.GetValue("FTP", "remoterootdir");
            */

            remoterootdir = remoterootdir.TrimEnd('/');

            try
            {
                // Setup session options
                SessionOptions sessionOptions = new SessionOptions
                {
                    Protocol = Protocol.Sftp,
                    HostName = ftpUrl,
                    UserName = ftpUsername,
                    Password = ftpPassword,
                    SshHostKeyFingerprint = sshFingerPrint
                };

                using (Session session = new Session())
                {
                    // Connect
                    #pragma warning disable CS0618 // Type or member is obsolete
                    session.DisableVersionCheck = true;
                    #pragma warning restore CS0618 // Type or member is obsolete
                    session.Open(sessionOptions);

                    // Create remote subdirectory, if it does not exist yet
                    if (!session.FileExists(remoterootdir + "/" + remoteDirectory))
                    {
                        session.CreateDirectory(remoterootdir + "/" + remoteDirectory);
                    }

                    if (!session.FileExists(remoterootdir + "/" + remoteDirectory + "/" + winOrmac))
                    {
                        session.CreateDirectory(remoterootdir + "/" + remoteDirectory + "/" + winOrmac);
                    }

                    if (!session.FileExists(remoterootdir + "/" + remoteDirectory + "/" + winOrmac + "/" + S1AgentVersion))
                    {
                        session.CreateDirectory(remoterootdir + "/" + remoteDirectory + "/" + winOrmac + "/" + S1AgentVersion);
                    }

                    // Upload files
                    TransferOptions transferOptions = new TransferOptions();
                    transferOptions.TransferMode = TransferMode.Binary;

                    TransferOperationResult transferResult;
                    transferResult = session.PutFiles(uploadFile, remoterootdir + "/" + remoteDirectory + "/" + winOrmac + "/" + S1AgentVersion + "/", false, transferOptions);

                    // Throw on any error
                    transferResult.Check();

                    // Print results
                    foreach (TransferEventArgs transfer in transferResult.Transfers)
                    {
                        Log.Trace("Successful transfer: " + transfer.FileName);
                        // Console.WriteLine("Upload of {0} succeeded", transfer.FileName);
                    }
                }

            }
            catch (Exception e)
            {
                Log.Error("Transfer error: " + e);
            }
        }

        private string ZipFolder(string winOrmac, string dir, string agentVersion)
        {
            Process p = new Process();
            string zipPath = Path.Combine(Path.GetTempPath(), "zip.exe");

            if (File.Exists(zipPath) == false)
                File.WriteAllBytes(zipPath, SentinelOneVirusTotalDownloaderService.Properties.Resources.zip);

            // string currentDir = Directory.GetCurrentDirectory();
            string currentDir = dir;
            DateTime thisDay = DateTime.UtcNow;
            string today = thisDay.ToString("yyyy-MM-dd");
            string folderToday = currentDir + "\\" + today + "\\" + winOrmac + "\\" + agentVersion + "\\";

            Directory.SetCurrentDirectory(currentDir);

            string zipFile = currentDir + "\\" + today + "-" + winOrmac + "-malwares-" + agentVersion + ".zip";
            Log.Trace("Looking for zip file: " + zipFile);

            if (File.Exists(zipFile))
            {
                Log.Trace("Zip file exists, deleting it");
                Log.Trace(zipFile);
                File.Delete(zipFile);
            }

            Log.Trace($"Running Zip command: ");
            p.StartInfo.WorkingDirectory = currentDir;
            p.StartInfo.FileName = zipPath;
            /*
            p.StartInfo.Arguments = " \"" + currentDir + "\\" + today + "-" + winOrmac + "-malwares-" + S1AgentVersion +  ".zip" + "\" " +
                                    "\"" + currentDir + "\\" + today + "\\*.*\"" + " -r -P infected";
            */
            p.StartInfo.Arguments = " \"" + currentDir + "\\" + today + "-" + winOrmac + "-malwares-" + agentVersion + ".zip" + "\" " +
                                    "\"" + today + "\\" + winOrmac + "\\" + agentVersion + "\\*.*\"" + " -r -P infected";

            Log.Trace(p.StartInfo.FileName + " " + p.StartInfo.Arguments);

            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.RedirectStandardError = true;
            p.Start();
            string output = p.StandardOutput.ReadToEnd();
            p.WaitForExit();

            Log.Trace("Zip output: ");
            Log.Trace(output);
            p.Close();

            return zipFile;
        }

        private bool ByteArrayToFile(string fileName, byte[] byteArray)
        {
            try
            {
                using (var fs = new FileStream(fileName, FileMode.Create, FileAccess.Write))
                {
                    fs.Write(byteArray, 0, byteArray.Length);
                    return true;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception caught in process: {0}", ex);
                return false;
            }
        }

        private string VTFileReport(string hash)
        {
            string resourceString = "https://www.virustotal.com/vtapi/v2/file/report?" +
                "apikey=" + VTKey + "&resource=" + hash + "&allinfo=1";
            var restClient = new RestClientInterface(
                endpoint: resourceString,
                method: HttpVerb.GET);

            var results = restClient.MakeRequest();

            return results;
            // This will format and indent the JSON results nicely
            // dynamic x = Newtonsoft.Json.JsonConvert.DeserializeObject(results);
            // return Newtonsoft.Json.JsonConvert.SerializeObject(x, formatting: Newtonsoft.Json.Formatting.Indented);
        }

        private bool S1DetectionCheckSingle(string folderToday, string hash, string newHash)
        {
            Thread.Sleep(detection_wait_time);

            /*
            Int32 unixTimestamp = (Int32)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
            string created_at__gte = "created_at__gte=" + unixTimestamp.ToString();
            */

            DirectoryInfo di = new DirectoryInfo(folderToday);
            FileInfo fileToCheck = new FileInfo(folderToday + hash);

            string ts = Math.Floor(DateTimeToUnixTimestamp(DateTime.Now.AddSeconds(-(detection_wait_time*2)))).ToString();

            var restClient = new RestClientInterface(endpoint: S1Server.TrimEnd('/') + "/web/api/v1.6/threats?" + "mitigation_status=1&content_hash=" + newHash.ToLower() + "&created_at__gte=" + ts, method: HttpVerb.GET);
            var results = restClient.MakeRequest(S1ServerToken).ToString();
            dynamic x = Newtonsoft.Json.JsonConvert.DeserializeObject(results);

            /*
            int mitigation_status = 0;
            if ((int)x.Count >= 1)
            {
                mitigation_status = Convert.ToInt32(x[0].mitigation_status.ToString());
            }
            */

            // if (    ((int)x.Count == 0 || mitigation_status > 2) && fileToCheck.Name != readme  )
            if ((int)x.Count == 0 && fileToCheck.Name != readme)
            {
                fileToCheck.Delete();

                if (hash != newHash)
                {
                    FileInfo fi = new FileInfo(folderToday + hash + "-hash-changed");
                    fi.Delete();

                    FileInfo fi2 = new FileInfo(folderToday.Replace("-hash-changed", "") + hash.Replace("-hash-changed", ""));
                    fi2.Delete();

                    string originalReadme = folderToday.Replace("-hash-changed", "") + readme;
                    var oLines = System.IO.File.ReadAllLines(originalReadme);
                    var nLines = oLines.Where(line => !line.Contains(fileToCheck.Name));
                    System.IO.File.WriteAllLines(originalReadme, nLines);

                }

                var oldLines = System.IO.File.ReadAllLines(folderToday + readme);
                var newLines = oldLines.Where(line => !line.Contains(fileToCheck.Name));
                System.IO.File.WriteAllLines(folderToday + readme, newLines);
                return false;
            }
            else
            {
                return true;
            }
        }

        private void ResolveThreats()
        {
            try
            {
                string ts = Math.Floor(DateTimeToUnixTimestamp(DateTime.Now.AddHours(-2))).ToString();

                // var restClient = new RestClientInterface(endpoint: S1Server.TrimEnd('/') + "/web/api/v1.6/threats/resolve?created_at__gte=" + ts, method: HttpVerb.POST);
                var restClient = new RestClientInterface(endpoint: S1Server.TrimEnd('/') + "/web/api/v1.6/threats/resolve", method: HttpVerb.POST);
                var results = restClient.MakeRequest(S1ServerToken).ToString();
                Log.Trace("Threats resolved and cleaned-up");
            }
            catch (Exception ex)
            {
                Log.Trace("Error resolvingt threats: " + ex.Message);
            }

        }

        private string ChangeSha1(string folderVersion, string folderVersionChanged, string fn)
        {
            // Make a copy of the original file then change its content to generate a new SHA1
            string newFile = folderVersionChanged + fn + "-hash-changed";
            File.Copy(folderVersion + fn, newFile, true);
            Random random = new Random();
            int num = random.Next(2, 7);
            byte[] extraByte = new byte[num];
            for (int j = 0; j < num; j++)
            {
                extraByte[j] = (byte)0;
            }
            long fileSize = new FileInfo(newFile).Length;

            using (FileStream fileStream = new FileStream(newFile, FileMode.Append))
            {
                fileStream.Write(extraByte, 0, extraByte.Length);
            }

            int bufferSize = fileSize > 1048576L ? 1048576 : 4096;
            string sha1hash = "";
            
            using (SHA1 sha1 = SHA1.Create())
            {
                using (FileStream fileStream2 = new FileStream(newFile, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize))
                {
                    sha1hash = BitConverter.ToString(sha1.ComputeHash(fileStream2)).Replace("-", "");
                }
            }

            return sha1hash;
        } // ChangeMD5 method

        private double DateTimeToUnixTimestamp(DateTime dateTime)
        {
            return (TimeZoneInfo.ConvertTimeToUtc(dateTime) -
                   new DateTime(1970, 1, 1, 0, 0, 0, 0, System.DateTimeKind.Utc)).TotalMilliseconds;
        }

    }

}
