# 📊 Kosty Dashboard

A modern, premium dashboard to visualize AWS cost optimization audit results from Kosty.

## 🚀 Features

- **📈 Interactive Charts** - Bar charts and pie charts using Chart.js
- **🎨 Modern UI** - Built with React and Tailwind CSS
- **📱 Responsive Design** - Works on desktop, tablet, and mobile
- **🔄 Real-time Loading** - Drag & drop JSON file upload
- **📊 Multiple Views** - Service breakdown, issue distribution, detailed cards
- **🎯 Priority Levels** - High, medium, low severity indicators
- **💫 Premium Design** - Gradient backgrounds, shadows, animations

## 🎯 Quick Start

1. **Generate JSON Report**:
   ```bash
   kosty --all --output json
   # or
   kosty audit --output json
   ```

2. **Open Dashboard**:
   ```bash
   open dashboard/index.html
   ```

3. **Load Your Report**:
   - Click "Load JSON Report" button
   - Select your generated JSON file
   - View your optimization opportunities!

## 📊 Dashboard Sections

### 📈 **Stats Overview**
- Total issues found
- Accounts scanned
- Services checked
- High priority issues

### 📊 **Charts**
- **Issues by Service**: Bar chart showing which AWS services have the most issues
- **Issue Distribution**: Pie chart categorizing issues by type (Storage, Compute, Database, Network)

### 🎯 **Issue Cards**
- Service icons and names
- Issue descriptions
- Severity indicators (High/Medium/Low)
- Resource details (bucket names, instance IDs, etc.)

## 🎨 Design Features

- **Gradient Header**: Beautiful blue-purple gradient
- **Card Shadows**: Premium shadow effects
- **Color Coding**: 
  - 🔴 High priority (red)
  - 🟡 Medium priority (yellow)
  - 🟢 Low priority (green)
- **Icons**: Font Awesome icons for all services
- **Responsive Grid**: Adapts to screen size

## 🔧 Technical Stack

- **React 18**: Component-based UI
- **Tailwind CSS**: Utility-first styling
- **Chart.js**: Interactive charts
- **Font Awesome**: Service icons
- **Vanilla JS**: No build process required

## 📱 Usage Examples

### Load Sample Data
The dashboard includes sample data for demonstration. Upload your own JSON to see real results.

### Service Icons
- 🖥️ EC2: Server icon
- 🗄️ RDS: Database icon
- ☁️ S3: Cloud icon
- ⚡ Lambda: Bolt icon
- 💾 EBS: Hard drive icon
- 🌐 VPC: Network icon

### Issue Severity
- **High**: Oversized instances, unused read replicas
- **Medium**: Idle resources, lifecycle candidates
- **Low**: Empty buckets, orphaned resources

## 🚀 Deployment

### Local Usage
Simply open `index.html` in any modern browser.

### Web Server
```bash
# Python
python -m http.server 8000

# Node.js
npx serve .

# Then visit: http://localhost:8000
```

### Static Hosting
Upload to any static hosting service:
- GitHub Pages
- Netlify
- Vercel
- AWS S3 + CloudFront

## 🎯 Example Workflow

1. **Run Audit**:
   ```bash
   kosty --organization --all --output json
   ```

2. **Open Dashboard**:
   ```bash
   open dashboard/index.html
   ```

3. **Analyze Results**:
   - View total issues in stats cards
   - Check service breakdown in bar chart
   - Review issue distribution in pie chart
   - Examine detailed issue cards

4. **Take Action**:
   - Prioritize high-severity issues
   - Focus on services with most issues
   - Use resource details to identify specific items

## 💡 Tips

- **Regular Audits**: Run weekly/monthly audits to track improvements
- **Team Sharing**: Share dashboard HTML file with team members
- **Historical Tracking**: Keep JSON reports to compare over time
- **Mobile Friendly**: View results on mobile devices
- **Print Ready**: Dashboard prints well for reports

The dashboard provides a beautiful, professional way to visualize and share your AWS cost optimization findings!