using System;
using System.Windows;
using System.IO;

namespace Nighthawk
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        private void Application_Startup(object sender, StartupEventArgs e)
        {
            AppDomain.CurrentDomain.UnhandledException += new UnhandledExceptionEventHandler(CurrentDomain_UnhandledException);
        }

        public void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            var exception = (Exception) e.ExceptionObject;
            var data = string.Empty;

            // get exception message (no need to say anything...)
            if (exception.InnerException != null)
            {
                if (exception.InnerException.InnerException != null)
                {
                    if (exception.InnerException.InnerException.InnerException != null)
                    {
                        data = exception.InnerException.InnerException.InnerException.Message + "\r\n" +
                               exception.InnerException.InnerException.InnerException.StackTrace;
                    }
                    else
                    {
                        data = exception.InnerException.InnerException.Message + "\r\n" +
                               exception.InnerException.InnerException.StackTrace;
                    }
                }
                else
                {
                    data = exception.InnerException.Message + "\r\n" +
                           exception.InnerException.StackTrace;
                }
            }
            else
            {
                data = exception.Message + "\r\n" +
                       exception.StackTrace;
            }

            // save to file
            var file = File.Create("nighthawk-error-log.txt");
            var stream = new StreamWriter(file);

            stream.Write(data);
            stream.Close();
            file.Close();
        }
    }
}
