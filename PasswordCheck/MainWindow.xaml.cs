using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using PasswordCheck.Security;

namespace PasswordCheck
{
    
    public partial class MainWindow : Window
    {
        private Thread _checkThread;
        private bool _running;        
        private DispatcherTimer _timer;
        private string _result;
        private string _pw_filepath;
        private CHECK_TYPE _check_type;
        private string _user_pw;

        enum CHECK_TYPE
        {
            SHA1,
            NTLM
        }

        public MainWindow()
        {
            InitializeComponent();            
            _timer = new DispatcherTimer() { Interval = TimeSpan.FromMilliseconds(250) };            
            _timer.Tick += _timer_Tick;
            _timer.Start();

            //_pw_filepath = @"D:\Downloads\pwned-passwords-sha1-ordered-by-count-v4\pwned-passwords-sha1-ordered-by-count-v4.txt";
            //txtFilePath.Text = _pw_filepath;
        }

        //Dispatcher
        private void _timer_Tick(object sender, EventArgs e)
        {
            _timer.IsEnabled = false;
            if (_result != null)
                blkResults.Text = _result;

            if (!_running && pbRunning.IsIndeterminate)
                pbRunning.IsIndeterminate = false;
            else if (_running && !pbRunning.IsIndeterminate)
                pbRunning.IsIndeterminate = true;
            
            if(!_running && btnInitiate.Content.Equals("Stop Check"))
            {
                btnInitiate.Content = "Check Password";
            }

            _timer.IsEnabled = true;
        }

        private void BtnInitiate_Click(object sender, RoutedEventArgs e)
        {
            if(btnInitiate.Content.Equals("Check Password"))
            {
                _InitiateCheck();
                btnInitiate.Content = "Stop Check";
            }
            else
            {
                if (_checkThread != null && _checkThread.IsAlive)
                {
                    var mbr = MessageBox.Show(this, "Are you sure you'd like to end the check?", "Password Checker", MessageBoxButton.YesNo, MessageBoxImage.Question);
                    if (mbr == MessageBoxResult.Yes)
                    {
                        _running = false;
                        _checkThread.Abort();                        
                        btnInitiate.Content = "Check Password";
                    }
                }
            }
        }
        private void _InitiateCheck()
        { 
            if(_pw_filepath.ToLower().Contains("ntlm"))
            {
                _check_type = CHECK_TYPE.NTLM;
                MessageBoxResult dr = MessageBox.Show(this, "Initiating NTLM password check based on file name.\nIs this correct? (No will start SHA-1 Check)", "Password Checker", MessageBoxButton.YesNo, MessageBoxImage.Question);
                if(dr == MessageBoxResult.No)
                {
                    _check_type = CHECK_TYPE.SHA1;
                }
            }
            else //SHA1 assumed
            {
                _check_type = CHECK_TYPE.SHA1;
                MessageBoxResult dr = MessageBox.Show(this, "Initiating SHA-1 password check based on file name.\nIs this correct? (No will start NTLM Check)", "Password Checker", MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (dr == MessageBoxResult.No)
                {
                    _check_type = CHECK_TYPE.NTLM;
                }
            }
            if(_checkThread != null && _checkThread.IsAlive)
            {
                MessageBoxResult dr = MessageBox.Show(this, "Do you want to cancel the current check?", "Password Checker", MessageBoxButton.YesNo, MessageBoxImage.Exclamation);
                if (dr == MessageBoxResult.Yes)
                {
                    _checkThread.Abort();
                    _checkThread = null;
                    _running = false;

                }
                else
                {
                    return;
                }
            }
            _result = ""; //purge last result
            _user_pw = txtPassword.Text;
            if(string.IsNullOrEmpty(_user_pw))
            {
                MessageBox.Show(this, "Please enter a password to check.", "Password Checker", MessageBoxButton.OK, MessageBoxImage.Exclamation);
                return;
            }
            
            _checkThread = new Thread(new ThreadStart(_Check));
            _checkThread.Start();
        }
        

        private void _Check()
        {
            string password = _user_pw;

            _running = true;
            StreamReader reader = new StreamReader(_pw_filepath);

            if (_check_type == CHECK_TYPE.SHA1)
                password = SecurityUtils.HashSHA1(password);
            else
                password = SecurityUtils.HashNLTM(password);

            int _counter = 0;
            while(!reader.EndOfStream)
            {
                string password_line = reader.ReadLine();
                password_line = password_line.Split(':').First();
                if (password_line.Equals(password))
                {
                    _result = "Password Found :(";
                    break;
                }
                if (++_counter > 5)
                    _result = string.Format("Checked {0} Passwords", _counter);
            }

            if (string.IsNullOrEmpty(_result))
                _result = "Password Not Found :)";

            reader.Close();
            _running = false;
        }

        private void TxtFilePath_MouseUp(object sender, MouseButtonEventArgs e)
        {
            Microsoft.Win32.OpenFileDialog ofd = new Microsoft.Win32.OpenFileDialog() { Filter = "Text file|*.txt" };
            bool? dr = ofd.ShowDialog(this);
            if (dr.HasValue && dr.Value == false)
                return;
            txtFilePath.Text = ofd.FileName;
            _pw_filepath = ofd.FileName;
        }

        private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            if(_checkThread != null && _checkThread.IsAlive)
            {
                //confirm exit
                var mbr = MessageBox.Show(this, "Password check is in progress, are you sure you'd like to exit?", "Password Checker", MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (mbr == MessageBoxResult.No)
                {
                    e.Cancel = true;
                    return;
                }
                _checkThread.Abort();                
            }
        }
    }
}
