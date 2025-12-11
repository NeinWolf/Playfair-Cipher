using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows;

namespace Playfair_UI_App
{
    public partial class MainWindow : Window
    {
        // ---------------------------------------------------------
        // DLL IMPORTS (Must match your C/ASM .h file signatures)
        // ---------------------------------------------------------

        // Import C Implementation
        [DllImport("Playfair_C_DLL.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void BuildKeyTable_C(byte[] table, string key);

        [DllImport("Playfair_C_DLL.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void EncryptPlayfair_C(byte[] table, string plaintext, StringBuilder ciphertext);

        [DllImport("Playfair_C_DLL.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void DecryptPlayfair_C(byte[] table, string ciphertext, StringBuilder plaintext);

        // Import ASM Implementation
        [DllImport("Playfair_ASM_DLL.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void BuildKeyTable_ASM(byte[] table, string key);

        [DllImport("Playfair_ASM_DLL.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void EncryptPlayfair_ASM(byte[] table, string plaintext, StringBuilder ciphertext);

        [DllImport("Playfair_ASM_DLL.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void DecryptPlayfair_ASM(byte[] table, string ciphertext, StringBuilder plaintext);

        public MainWindow()
        {
            InitializeComponent();
        }

        // Helper to run the logic generically
        private void ProcessCipher(bool useAsm)
        {
            try
            {
                string key = TxtKey.Text;
                string input = TxtInput.Text;
                bool isEncrypt = RbEncrypt.IsChecked == true;

                // 1. Prepare Buffer
                // Playfair can increase length slightly due to padding (inserting X between double letters)
                // We allocate 2x length just to be safe.
                StringBuilder outputBuffer = new StringBuilder(input.Length * 2 + 50);

                // The Key Table is 5x5 = 25 chars. Byte array is safer than string for raw buffers.
                byte[] keyTable = new byte[25];

                // 2. Start Benchmark
                Stopwatch sw = Stopwatch.StartNew();

                if (useAsm)
                {
                    // Call Assembly Functions
                    BuildKeyTable_ASM(keyTable, key);
                    if (isEncrypt)
                        EncryptPlayfair_ASM(keyTable, input, outputBuffer);
                    else
                        DecryptPlayfair_ASM(keyTable, input, outputBuffer);
                }
                else
                {
                    // Call C Functions
                    BuildKeyTable_C(keyTable, key);
                    if (isEncrypt)
                        EncryptPlayfair_C(keyTable, input, outputBuffer);
                    else
                        DecryptPlayfair_C(keyTable, input, outputBuffer);
                }

                sw.Stop();

                // 3. Update UI
                TxtOutput.Text = outputBuffer.ToString();

                string mode = useAsm ? "ASM (AVX2)" : "C (Standard)";
                string op = isEncrypt ? "Encryption" : "Decryption";
                long time = sw.ElapsedTicks;

                LblStatus.Text = $"{mode} {op} completed in {time} ticks ({sw.Elapsed.TotalMilliseconds:F4} ms).";
            }
            catch (DllNotFoundException ex)
            {
                MessageBox.Show($"Could not find the DLL: {ex.Message}\n\nMake sure the C and ASM DLLs are in the same folder as this executable.", "DLL Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error: {ex.Message}", "Runtime Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void BtnRunC_Click(object sender, RoutedEventArgs e)
        {
            ProcessCipher(useAsm: false);
        }

        private void BtnRunAsm_Click(object sender, RoutedEventArgs e)
        {
            ProcessCipher(useAsm: true);
        }
    }
}