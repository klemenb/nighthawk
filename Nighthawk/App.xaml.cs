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
            NBug.Settings.StoragePath = NBug.Enums.StoragePath.CurrentDirectory;
            NBug.Settings.UIMode = NBug.Enums.UIMode.Full;
            NBug.Settings.UIProvider = NBug.Enums.UIProvider.WPF;
            NBug.Settings.WriteLogToDisk = false;
            NBug.Settings.ReleaseMode = true;

            #if !DEBUG
            AppDomain.CurrentDomain.UnhandledException += NBug.Handler.UnhandledException;
            Current.DispatcherUnhandledException += NBug.Handler.DispatcherUnhandledException;
            #endif
        }
    }
}
