using System;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Text;
using System.Windows.Forms;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace DataVault {
	class DataVault {
		private enum en_de_cryption_mode {
			encrypt,
			decrypt
		}

		private static void en_de_crypt(en_de_cryption_mode en_de_cryption_mode_current,
						string file_path_from,
						string file_path_to,
						bool delete_file_path_from,
						bool interactive)
		{
			Form form = new Form();
			
			Label password_1_label = new Label(),
			      password_2_label = new Label();
			      
			int label_width = 150,
			    label_height = 20,
			    textbox_width = 200,
			    textbox_height = 20,
			    button_width = 80,
			    button_height = 40;
			
			Color label_forecolor = Color.LightGreen,
			      password_backcolor = Color.Black,
			      password_forecolor = Color.LightGreen,
			      proceed_backcolor = Color.Black,
			      proceed_forecolor = Color.LightGreen,
			      cancel_backcolor = Color.Black,
			      cancel_forecolor = Color.LightGreen,
			      error_forecolor = Color.Red;
			
			ContentAlignment label_text_alignment = ContentAlignment.MiddleRight,
					 button_text_alignment = ContentAlignment.MiddleCenter;
			
			TextBox password_1 = new TextBox(),
				password_2 = new TextBox();
			
			char password_character = '*';
			
			BorderStyle password_border_style = BorderStyle.Fixed3D;
			
			Font label_font = new Font(FontFamily.GenericMonospace, (float)10.0),
			     password_font = new Font(FontFamily.GenericMonospace, (float)10.0),
			     button_font = new Font(FontFamily.GenericMonospace, (float)10.0);
			
			Button proceed = new Button(),
			       cancel = new Button();

			form.StartPosition = FormStartPosition.CenterParent;
			form.Width = 400;
			form.Height = 180;
			form.BackColor = Color.Black;
			form.Text = "Please, provide the password for the " +
				    (en_de_cryption_mode_current == en_de_cryption_mode.encrypt ?
					    "encryption" : "decryption") +
				    ".";

			password_1_label.Bounds = new Rectangle(10, 20, label_width, label_height);
			password_1_label.Font = label_font;
			password_1_label.ForeColor = label_forecolor;
			password_1_label.TextAlign = label_text_alignment;
			password_1_label.Text = "Password:";

			password_2_label.Bounds = new Rectangle(10, 50, label_width, label_height);
			password_2_label.Font = label_font;
			password_2_label.ForeColor = label_forecolor;
			password_2_label.TextAlign = label_text_alignment;
			password_2_label.Text = "Confirm password:";

			password_1.Bounds = new Rectangle(160, 20, textbox_width, textbox_height);
			password_1.BackColor = password_backcolor;
			password_1.ForeColor = password_forecolor;
			password_1.BorderStyle = password_border_style;
			password_1.PasswordChar = password_character;
			password_1.Font = password_font;
			password_1.Multiline = false;
			password_1.KeyUp += (sender, e) =>
			{
				if ((Keys)e.KeyValue == Keys.Escape)
					cancel.GetType()
					      .GetMethod("OnClick",
							 BindingFlags.Instance |
								 BindingFlags.NonPublic)
					      .Invoke(cancel, new object[] { null });

				if (en_de_cryption_mode_current == en_de_cryption_mode.encrypt) {
					if (!string.IsNullOrEmpty(password_1.Text)) {
						password_2.Enabled = true;
					} else {
						proceed.Enabled = false;
						password_2.Text = "";
						if (password_2.Enabled)
							password_2.Enabled = false;
					}
				} else {
					if (!string.IsNullOrEmpty(password_1.Text))
						proceed.Enabled = true;
					else
						proceed.Enabled = false;
				}

				if ((Keys)e.KeyValue == Keys.Enter &&
				    !string.IsNullOrEmpty(password_1.Text)) {
					if (en_de_cryption_mode_current == en_de_cryption_mode.encrypt)
						password_2.Focus();
					else
						proceed.GetType()
						       .GetMethod("OnClick",
									  BindingFlags.Instance |
										  BindingFlags.NonPublic)
						       .Invoke(proceed,
							       new object[] { new KeyEventArgs(Keys.Enter) });
				}
			};

			password_2.Bounds = new Rectangle(160, 50, textbox_width, textbox_height);
			password_2.BackColor = password_backcolor;
			password_2.ForeColor = password_forecolor;
			password_2.BorderStyle = password_border_style;
			password_2.PasswordChar = password_character;
			password_2.Font = password_font;
			password_2.Multiline = false;
			password_2.Enabled = false;
			if (en_de_cryption_mode_current == en_de_cryption_mode.encrypt)
				password_2.KeyUp += (sender, e) =>
				{
					if ((Keys)e.KeyValue == Keys.Escape)
						cancel.GetType()
						      .GetMethod("OnClick",
								 BindingFlags.Instance |
									 BindingFlags.NonPublic)
						      .Invoke(cancel, new object[] { null });
					
					if (string.IsNullOrEmpty(password_2.Text) ||
						password_1.Text.Equals(password_2.Text)) {
						if (!string.IsNullOrEmpty(password_2.Text))
							proceed.Enabled = true;
						password_2.ForeColor = password_forecolor;
						if ((Keys)e.KeyValue == Keys.Enter &&
							!string.IsNullOrEmpty(password_2.Text))
							proceed.GetType()
							       .GetMethod("OnClick",
									  BindingFlags.Instance |
										  BindingFlags.NonPublic)
							       .Invoke(proceed,
								       new object[] { new KeyEventArgs(Keys.Enter) });
					} else {
						proceed.Enabled = false;
						password_2.ForeColor = error_forecolor;
					}
				};

			proceed.Bounds = new Rectangle(290, 100, button_width, button_height);
			proceed.BackColor = proceed_backcolor;
			proceed.ForeColor = proceed_forecolor;
			proceed.Font = button_font;
			proceed.TextAlign = button_text_alignment;
			proceed.Text = "Proceed";
			proceed.Enabled = false;
			proceed.Click += (sender, e) =>
			{
				form.Close();

				byte[] key_string_bytes = Encoding.UTF8.GetBytes(password_1.Text), key = new byte[64];

				password_1.Text = "";
				password_2.Text = "";

				FileStream file_from = null, file_to = null;

				try {
					WhirlpoolDigest whirlpool_digest = new WhirlpoolDigest();

					whirlpool_digest.BlockUpdate(key_string_bytes, 0, key_string_bytes.Length);
					whirlpool_digest.DoFinal(key, 0);

					SerpentEngine serpent_engine = new SerpentEngine();

					Pkcs7Padding pkcs7_padding = new Pkcs7Padding();
					pkcs7_padding.Init(new SecureRandom(key));

					PaddedBufferedBlockCipher
						padded_buffered_block_cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(serpent_engine),
                                                             						     pkcs7_padding);

					byte[] iv = new byte[padded_buffered_block_cipher.GetBlockSize()];
					Array.Copy(key, key.Length - iv.Length, iv, 0, iv.Length);

					padded_buffered_block_cipher.Init((en_de_cryption_mode_current == en_de_cryption_mode.encrypt),
									  new ParametersWithIV(new KeyParameter(key, 31, 32),
											       iv));

					int plaintext_buffer_size = 1000 * padded_buffered_block_cipher.GetBlockSize(),
					    ciphertext_buffer_size = padded_buffered_block_cipher.GetBlockSize() +
								     plaintext_buffer_size,
					    bytes_read_count,
					    bytes_en_de_crypted_count;

					byte[] buffer_from, buffer_to;

					if (en_de_cryption_mode_current == en_de_cryption_mode.encrypt) {
						buffer_from = new byte[plaintext_buffer_size];
						buffer_to = new byte[ciphertext_buffer_size];
					} else {
						buffer_from = new byte[ciphertext_buffer_size];
						buffer_to = new byte[plaintext_buffer_size];
					}

					file_from = new FileStream(file_path_from, FileMode.Open);
					file_to = new FileStream(file_path_to, FileMode.Create);

					while (true) {
						bytes_read_count = file_from.Read(buffer_from, 0, buffer_from.Length);
						if (bytes_read_count == 0) {
							break;
						}
						bytes_en_de_crypted_count = padded_buffered_block_cipher.DoFinal(buffer_from,
														 0,
														 bytes_read_count,
														 buffer_to,
														 0);
						file_to.Write(buffer_to, 0, bytes_en_de_crypted_count);
					}

					file_from.Close();
					file_to.Close();

					if (delete_file_path_from)
						File.Delete(file_path_from);

					for (int i = 0; i < key_string_bytes.Length; i += 1)
						key_string_bytes[i] = 0;
					for (int i = 0; i < key.Length; i += 1)
						key[i] = 0;
					whirlpool_digest.Reset();
					serpent_engine.Reset();
					pkcs7_padding = null;
					padded_buffered_block_cipher.Reset();
					for (int i = 0; i < iv.Length; i += 1)
						iv[i] = 0;
					for (int i = 0; i < buffer_from.Length; i += 1)
						buffer_from[i] = 0;
					for (int i = 0; i < buffer_to.Length; i += 1)
						buffer_to[i] = 0;
				} catch(Exception exception) {
					string message;
					if (exception.Message.Contains("pad block corrupted")) {
						if (file_from != null) {
							file_from.Close();
						}
						if (file_to != null) {
							file_to.Close();
						}
						try {
							File.Delete(file_path_to);
						} catch(Exception) {}
						message = "A wrong decryption key has been provided.";
					} else {
						message = exception.Message;
					}
					alert(message, interactive);
				}
			};

			cancel.Bounds = new Rectangle(200, 100, button_width, button_height);
			cancel.BackColor = cancel_backcolor;
			cancel.ForeColor = cancel_forecolor;
			cancel.Font = button_font;
			cancel.TextAlign = button_text_alignment;
			cancel.Text = "Cancel";
			cancel.Click += (sender, e) =>
			{
				form.Close();

				password_1.Text = "";
				password_2.Text = "";

			};

			form.Controls.Add(password_1_label);
			form.Controls.Add(password_2_label);
			form.Controls.Add(password_1);
			form.Controls.Add(password_2);
			form.Controls.Add(proceed);
			form.Controls.Add(cancel);

			form.ShowDialog();
		}

		private static void print_usage(string error_message = null, bool interactive = false)
		{
			string message = "";
			
			if (!string.IsNullOrEmpty(error_message))
				message = error_message + "\n\n\n";
			message += "usage: DataVault.exe ([-h] | [-p] (-e | -d) [source_file_path] [destination_file_path])\n\n" +
				   "\t-h                   \tDisplay this help message.\n" +
				   "\t-p                   \tPreserve the source file.\n" +
				   "\t-e                   \tEncrypt the source file (must not be used with -d).\n" +
				   "\t-d                   \tDecrypt the source file (must not be used with -e).\n" +
				   "\tsource_file_path     \tThe path to the source file to encrypt/decrypt.\n" +
				   "\tdestination_file_path\tThe path to the destination file.";
			
			alert(message, interactive, !string.IsNullOrEmpty(error_message));
		}
		
		private static void alert(string message, bool interactive = false, bool error = true)
		{
			if (!interactive)
				Console.WriteLine(message);
			else
				MessageBox.Show(message);
			
			System.Diagnostics.Debug.WriteLine(message);
			
			Environment.Exit(!error ? 0 : 1);
		}

		public static int Main(string[] args)
		{
			if (args.Length == 0 ||
			    (args.Length == 1 && args[0].ToLower().Equals("-h"))) {
				print_usage();
			} else if (args.Length > 4) {
				print_usage("A wrong number of arguments has been provided.");
			} else {
				string arg1, arg2;
				bool interactive = false;
				
				if (args.Length == 1) {
					arg1 = args[0].ToLower().Trim();
					if (!arg1.Equals("-e") &&
					    !arg1.Equals("-d"))
						print_usage("At most one of -e or -d is necessary.");
					interactive = true;
				}
				
				if (args.Length == 2) {
					arg1 = args[0].ToLower().Trim();
					arg2 = args[1].ToLower().Trim();
					if ((arg1.Equals("-p") && arg2.Equals("-e")) ||
					    (arg1.Equals("-e") && arg2.Equals("-p")) ||
					    (arg1.Equals("-p") && arg2.Equals("-d")) ||
					    (arg1.Equals("-d") && arg2.Equals("-p")))
						interactive = true;
				}
				
				en_de_cryption_mode? en_de_cryption_mode_current = null;
				bool preserve_file_path_from = false;
				string file_path_from = null, file_path_to = null;
				
				if (interactive) {
					OpenFileDialog open_file_dialog = new OpenFileDialog();
					open_file_dialog.Title = "Please, provide the source file.";
					open_file_dialog.InitialDirectory = Environment.CurrentDirectory;
					open_file_dialog.Filter = "All files (*.*)|*.*|All files (*.*)|*.*";
					open_file_dialog.FilterIndex = 2;
					open_file_dialog.RestoreDirectory = true;
					if(open_file_dialog.ShowDialog() == DialogResult.OK)
						file_path_from = open_file_dialog.FileName;
					else
						return 0;
					
					SaveFileDialog save_file_dialog = new SaveFileDialog();
					save_file_dialog.Title = "Please, provide the destination file.";
					save_file_dialog.InitialDirectory = new FileInfo(file_path_from).Directory.FullName;
					save_file_dialog.Filter = "All files (*.*)|*.*|All files (*.*)|*.*";
					save_file_dialog.FilterIndex = 2;
					save_file_dialog.RestoreDirectory = true;
					save_file_dialog.OverwritePrompt = false;
					if(save_file_dialog.ShowDialog() == DialogResult.OK)
						file_path_to = save_file_dialog.FileName;
					else
						return 0;
				}

				string arg_lowered;
				foreach (string arg in args) {
					arg_lowered = arg.ToLower().Trim();
					if (arg_lowered.Equals("-h")) {
						print_usage();
					} else if (arg_lowered.Equals("-e")) {
						if (en_de_cryption_mode_current.HasValue) {
							if (en_de_cryption_mode_current.Value != en_de_cryption_mode.decrypt)
								en_de_cryption_mode_current = en_de_cryption_mode.encrypt;
							else
								print_usage("Cannot use both -e and -d.",
									    interactive);
						} else {
							en_de_cryption_mode_current = en_de_cryption_mode.encrypt;
						}
					} else if (arg_lowered.Equals("-d")) {
						if (en_de_cryption_mode_current.HasValue) {
							if (en_de_cryption_mode_current.Value != en_de_cryption_mode.encrypt)
								en_de_cryption_mode_current = en_de_cryption_mode.decrypt;
							else
								print_usage("Cannot use both -e and -d.",
									    interactive);
						} else {
							en_de_cryption_mode_current = en_de_cryption_mode.decrypt;
						}
					} else if (arg_lowered.Equals("-p")) {
						preserve_file_path_from = true;
					} else {
						if (string.IsNullOrEmpty(file_path_from))
							file_path_from = arg.Trim();
						else if (string.IsNullOrEmpty(file_path_to))
							file_path_to = arg.Trim();
						else
							print_usage("Found invalid argument: \"" +
								    arg.Trim() +
								    "\".");
					}
				}

				if (!en_de_cryption_mode_current.HasValue)
					print_usage("At most, one of -e or -d is necessary.");
				
				if (string.IsNullOrEmpty(file_path_from))
					print_usage("No source file path has been provided " +
						    "for encryption/decryption.");
				else if (!File.Exists(file_path_from))
					print_usage("The provided source file path \"" +
						    file_path_from +
						    "\" does not exist.");
				else if (Directory.Exists(file_path_from))
					alert("The source file path cannot be a directory.");
				
				if (string.IsNullOrEmpty(file_path_to)) {
					if (en_de_cryption_mode_current.Value == en_de_cryption_mode.encrypt) {
						file_path_to = file_path_from + ".encrypted";
						while (File.Exists(file_path_to))
							file_path_to += ".encrypted";
					} else {
						string file_path_from_lowered = file_path_from.ToLower();
						if (file_path_from_lowered.EndsWith(".encrypted") &&
						    !file_path_from_lowered.Equals(".encrypted"))
						    file_path_to = file_path_from.Substring(0,
											    file_path_from.Length - 10);
						else
							file_path_to = file_path_from + ".decrypted";
						while (File.Exists(file_path_to))
							file_path_to += ".decrypted";
					}
				}
				
				if (file_path_from.Equals(file_path_to))
					alert("The source file path cannot be the same as the " +
					      "destination file path.",
					      interactive);
                                
                                if (Directory.Exists(file_path_to))
                                        alert("The destination file path cannot be a directory.");
                                
				en_de_crypt(en_de_cryption_mode_current.Value,
					    file_path_from,
					    file_path_to,
					    !preserve_file_path_from,
					    interactive);
			}
			
			return 0;
		}
	}
}
